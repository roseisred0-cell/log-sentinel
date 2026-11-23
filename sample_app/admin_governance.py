"""
Phan quyen admin cua SOC Console (muc "Phan quyen").

Giao dien cho web app:
    Governance(store, identity, clock, local_principal)
        has_pin / set_pin / check_pin / reset_pin        - PIN rieng 6 so cua tung admin
        summary()                                        - so admin Cognito, che do khoi tao (hien ca khi chua mo PIN)
        pending_requests()                               - yeu cau dang cho bo phieu
        create_request(principal, action, username)      - tao yeu cau nang/ha/vo hieu hoa (nguoi tao = 1 phieu)
        vote(principal, request_id, approve)             - dong y / tu choi; du phieu thi thuc thi ngay
        ensure_may_manage_viewers(principal)             - admin noi bo chi thu hoi Nguoi xem trong che do khoi tao
    required_approvals(action, admin_count)              - so phieu can co
    MemoryGovernanceStore / DynamoGovernanceStore        - luu tren RAM (test) / IncidentTable

`principal` = "<auth>:<user>", vd "local:admin", "cognito:a@x.co".
`identity` = CognitoIdentity (hoac ban gia): list_users / promote / demote / disable.

Quy tac (docs/NHAT_KY_2026-11-11.md muc 3, docs/NHAT_KY_2026-11-12.md muc 1):
  - nang / ha Quan tri: da so admin dong y, toi thieu 2 phieu; nguoi bi ha khong bo phieu
  - vo hieu hoa: 2 nguoi. Mot phieu tu choi huy yeu cau. Yeu cau het han sau 24 gio.
  - luon toi thieu 2 admin Cognito: chan ha / vo hieu hoa lam so admin xuong duoi 2
  - che do khoi tao (duoi 2 admin Cognito): admin noi bo duoc bo phieu va tu minh nang mot nguoi len Quan tri;
    du 2 admin Cognito thi admin noi bo mat quyen bo phieu.
"""
import contextlib
import hashlib
import hmac
import secrets
import time
from typing import Callable, Optional

UNLOCK_SECONDS = 10 * 60
PIN_MAX_FAILURES = 5
PIN_LOCK_SECONDS = 15 * 60
REQUEST_TTL_SECONDS = 24 * 3600
MIN_ADMINS = 2
ACTIONS = ("promote", "demote", "disable")


# ------------------------------------------------------------------ errors
class GovernanceError(Exception):
    """Goc cua moi loi nghiep vu. `code` la chuoi tra ve cho trinh duyet, `http` la ma HTTP goi y."""
    code, http = "governance_error", 400


class PinExists(GovernanceError):
    code = "pin_exists"


class WeakPin(GovernanceError):
    code = "weak_pin"


class WrongPin(GovernanceError):
    code, http = "wrong_pin", 403

    def __init__(self, just_locked: bool = False):
        super().__init__()
        self.just_locked = just_locked  # lan sai nay vua lam khoa PIN -> web app phat canh bao


class PinLocked(GovernanceError):
    code, http = "pin_locked", 423


class InvalidRequest(GovernanceError):
    code = "invalid_request"


class InvalidTarget(GovernanceError):
    code = "invalid_target"


class SelfAction(GovernanceError):
    code = "self_action"


class MinAdmins(GovernanceError):
    code, http = "min_admins", 409


class NotEnoughAdmins(GovernanceError):
    code, http = "not_enough_admins", 409


class LocalAdminNoVote(GovernanceError):
    code, http = "local_admin_no_vote", 403


class NotAVoter(GovernanceError):
    code, http = "not_a_voter", 403


class AlreadyVoted(GovernanceError):
    code, http = "already_voted", 409


class RequestClosed(GovernanceError):
    code, http = "request_closed", 409


class RequestExpired(GovernanceError):
    code, http = "request_expired", 410


class RequestNotFound(GovernanceError):
    code, http = "not_found", 404


class ExecutionFailed(GovernanceError):
    code, http = "execution_failed", 409


class Busy(GovernanceError):
    """Mot worker khac dang thuc thi thao tac phan quyen; thu lai sau vai giay."""
    code, http = "busy", 409


class NotAdmin(GovernanceError):
    code, http = "not_admin", 403


class LocalAdminRestricted(GovernanceError):
    """Ngoai che do khoi tao, admin noi bo chi con xem, go khoa IP va duyet Nguoi xem."""
    code, http = "local_admin_restricted", 403


class ChangeFailed(GovernanceError):
    """Cognito loi khi thuc thi. Yeu cau van cho, nguoi da bo phieu bam lai de thu lai."""
    code, http = "upstream", 502

    def __init__(self, outcome: dict):
        super().__init__()
        self.outcome = outcome


EXECUTE_LOCK, EXECUTE_LOCK_SECONDS = "execute", 30


# ------------------------------------------------------------ vote rules
def required_approvals(action: str, admin_count: int) -> int:
    """
    So phieu dong y can co (nguoi tao yeu cau tinh mot phieu). `admin_count` = tong so admin, KE CA nguoi bi
    ha (quyet dinh A1 ngay 12/11: 4 admin -> 3 phieu); nguoi bi ha van khong duoc bo phieu.
      promote / demote: da so (qua nua), toi thieu 2.   disable: 2.
    """
    if action == "disable":
        return 2
    if action in ("promote", "demote"):
        return max(2, admin_count // 2 + 1)
    raise ValueError(action)


def is_weak_pin(pin) -> bool:
    """PIN hop le: dung 6 chu so ASCII, khong thuoc cac mau de doan."""
    if not isinstance(pin, str) or len(pin) != 6 or not all("0" <= c <= "9" for c in pin):
        return True
    digits = [int(c) for c in pin]
    steps = {b - a for a, b in zip(digits, digits[1:])}
    return (len(set(pin)) <= 2                               # 000000, 121212, 111222
            or steps in ({1}, {-1})                          # 123456, 987654
            or pin[:3] == pin[3:]                            # 123123
            or pin[0::2] == pin[1::2])                       # 112233


def _hash_pin(pin: str, salt: bytes) -> str:
    return hashlib.scrypt(pin.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32).hex()


def _is_local(principal: str) -> bool:
    return principal.startswith("local:")


# ------------------------------------------------------------------ store
class MemoryGovernanceStore:
    """Cung giao dien voi DynamoGovernanceStore. Moi thao tac la nguyen tu (nhu UpdateItem co dieu kien)."""

    def __init__(self):
        self.pins, self.requests, self.locks = {}, {}, {}

    # PIN
    def pin_get(self, principal: str) -> Optional[dict]:
        rec = self.pins.get(principal)
        return dict(rec) if rec else None

    def pin_create(self, principal: str, pin_hash: str, salt: str) -> bool:
        """False neu da co PIN (khong bao gio ghi de)."""
        if principal in self.pins:
            return False
        self.pins[principal] = {"hash": pin_hash, "salt": salt, "failures": 0, "locked_until": 0}
        return True

    # khoa thuc thi dung chung moi worker
    def lock_acquire(self, name: str, now: float, lease_seconds: float, owner: str) -> bool:
        if self.locks.get(name, (0, ""))[0] > now:
            return False
        self.locks[name] = (now + lease_seconds, owner)
        return True

    def lock_release(self, name: str, owner: str) -> None:
        """Chi chu khoa moi nha duoc: worker cham qua han khong mo khoa cua worker da lay lai khoa sau no."""
        if self.locks.get(name, (0, ""))[1] == owner:
            self.locks[name] = (0, "")

    def pin_fail(self, principal: str) -> int:
        rec = self.pins[principal]
        rec["failures"] += 1
        return rec["failures"]

    def pin_lock(self, principal: str, until: float) -> None:
        self.pins[principal].update(failures=0, locked_until=until)

    def pin_clear_failures(self, principal: str) -> None:
        self.pins[principal]["failures"] = 0

    def pin_delete(self, principal: str) -> None:
        self.pins.pop(principal, None)

    # yeu cau cho duyet
    def req_put(self, req: dict) -> None:
        self.requests[req["id"]] = {**req, "approvals": list(req["approvals"])}

    def req_get(self, request_id: str) -> Optional[dict]:
        req = self.requests.get(request_id)
        return {**req, "approvals": list(req["approvals"])} if req else None

    def req_list(self) -> list:
        return [self.req_get(i) for i in self.requests]

    def req_add_approval(self, request_id: str, principal: str) -> Optional[list]:
        """Them phieu neu yeu cau con cho. Tra ve danh sach phieu moi, hoac None neu yeu cau da dong."""
        req = self.requests[request_id]
        if req["status"] != "pending":
            return None
        if principal not in req["approvals"]:
            req["approvals"].append(principal)
        return list(req["approvals"])

    def req_finish(self, request_id: str, status: str) -> bool:
        """pending -> status. False neu da co worker khac dong yeu cau truoc (chi mot ben duoc thuc thi)."""
        req = self.requests[request_id]
        if req["status"] != "pending":
            return False
        req["status"] = status
        return True


class DynamoGovernanceStore:
    """
    Luu trong IncidentTable (dung chung voi su co), khoa rieng de IAM gioi han duoc (dynamodb:LeadingKeys):
        ADMIN_PIN#<principal> / "PIN"   hash, salt, failures, locked_until
        ROLE_REQ#<id>         / "REQ"   yeu cau cho duyet; record_type=ROLE_REQ de liet ke qua GSI by_type
    Ghi co dieu kien: bo dem sai PIN dung chung moi worker; dong yeu cau chi thanh cong mot lan.
    """
    PIN_SK, REQ_SK, REQ_TYPE = "PIN", "REQ", "ROLE_REQ"
    REQ_CLEANUP_SECONDS = 7 * 24 * 3600  # TTL chi de don rac (giu dau vet 1 tuan); han 24h kiem tra trong code

    def __init__(self, table_name: str, region: str):
        import threading
        self._name, self._region, self._threads = table_name, region, threading.local()

    @property
    def _table(self):
        # boto3 resource khong an toan khi dung chung giua cac luong (Gunicorn gthread) -> moi luong mot Table
        if not hasattr(self._threads, "table"):
            import boto3  # import tre: test khong can boto3
            self._threads.table = boto3.resource("dynamodb", region_name=self._region).Table(self._name)
        return self._threads.table

    @staticmethod
    def _num(value: float):
        from decimal import Decimal
        return Decimal(str(value))

    @staticmethod
    def _conditional_failed(exc: Exception) -> bool:
        return getattr(exc, "response", {}).get("Error", {}).get("Code") == "ConditionalCheckFailedException"

    def _pin_key(self, principal: str) -> dict:
        return {"incident_id": f"ADMIN_PIN#{principal}", "timestamp": self.PIN_SK}

    def _req_key(self, request_id: str) -> dict:
        return {"incident_id": f"ROLE_REQ#{request_id}", "timestamp": self.REQ_SK}

    # PIN
    def pin_get(self, principal: str) -> Optional[dict]:
        item = self._table.get_item(Key=self._pin_key(principal), ConsistentRead=True).get("Item")
        if not item:
            return None
        return {"hash": item["hash"], "salt": item["salt"], "failures": int(item.get("failures", 0)),
                "locked_until": float(item.get("locked_until", 0))}

    def _put_if(self, item: dict, condition: str, values: Optional[dict] = None) -> bool:
        """PutItem co dieu kien. False khi dieu kien khong dat (ConditionalCheckFailed)."""
        kwargs = {"Item": item, "ConditionExpression": condition}
        if values:
            kwargs["ExpressionAttributeValues"] = values
        try:
            self._table.put_item(**kwargs)
        except Exception as exc:
            if self._conditional_failed(exc):
                return False
            raise
        return True

    def pin_create(self, principal: str, pin_hash: str, salt: str) -> bool:
        return self._put_if({**self._pin_key(principal), "hash": pin_hash, "salt": salt,
                             "failures": 0, "locked_until": 0}, "attribute_not_exists(incident_id)")

    # khoa thuc thi: ROLE_REQ#LOCK#<name> (cung tien to IAM voi yeu cau, khong vao GSI vi khong co record_type)
    def _lock_key(self, name: str) -> dict:
        return {"incident_id": f"ROLE_REQ#LOCK#{name}", "timestamp": "LOCK"}

    def lock_acquire(self, name: str, now: float, lease_seconds: float, owner: str) -> bool:
        return self._put_if({**self._lock_key(name), "expires_at": self._num(now + lease_seconds),
                             "owner": owner, "ttl": int(now + 3600)},
                            "attribute_not_exists(incident_id) OR expires_at <= :now", {":now": self._num(now)})

    def lock_release(self, name: str, owner: str) -> None:
        # IAM khong cho xoa ROLE_REQ#*: mo khoa = dat het han ve 0. Chi khi minh con la chu khoa
        # (het han roi bi worker khac lay thi dieu kien sai -> bo qua, khong mo khoa cua nguoi khac).
        try:
            self._table.update_item(Key=self._lock_key(name), UpdateExpression="SET expires_at = :z",
                                    ConditionExpression="#o = :me", ExpressionAttributeNames={"#o": "owner"},
                                    ExpressionAttributeValues={":z": 0, ":me": owner})
        except Exception as exc:
            if not self._conditional_failed(exc):
                raise

    def pin_fail(self, principal: str) -> int:
        res = self._table.update_item(Key=self._pin_key(principal), UpdateExpression="ADD failures :one",
                                      ExpressionAttributeValues={":one": 1}, ReturnValues="UPDATED_NEW")
        return int(res["Attributes"]["failures"])

    def pin_lock(self, principal: str, until: float) -> None:
        self._table.update_item(Key=self._pin_key(principal), UpdateExpression="SET failures = :z, locked_until = :u",
                                ExpressionAttributeValues={":z": 0, ":u": self._num(until)})

    def pin_clear_failures(self, principal: str) -> None:
        self._table.update_item(Key=self._pin_key(principal), UpdateExpression="SET failures = :z",
                                ExpressionAttributeValues={":z": 0})

    def pin_delete(self, principal: str) -> None:
        self._table.delete_item(Key=self._pin_key(principal))

    # yeu cau cho duyet
    def req_put(self, req: dict) -> None:
        item = {**self._req_key(req["id"]), "record_type": self.REQ_TYPE, "request_id": req["id"],
                "action": req["action"], "target_username": req["target_username"],
                "target_email": req["target_email"], "initiator": req["initiator"],
                "approvals": set(req["approvals"]), "status": req["status"],
                "created_at": self._num(req["created_at"]),
                "ttl": int(req["created_at"]) + self.REQ_CLEANUP_SECONDS}
        self._table.put_item(Item=item, ConditionExpression="attribute_not_exists(incident_id)")

    @staticmethod
    def _req_view(item: dict) -> dict:
        return {"id": item["request_id"], "action": item["action"], "target_username": item["target_username"],
                "target_email": item["target_email"], "initiator": item["initiator"],
                "approvals": sorted(item.get("approvals", set())), "status": item["status"],
                "created_at": float(item["created_at"])}

    def req_get(self, request_id: str) -> Optional[dict]:
        item = self._table.get_item(Key=self._req_key(request_id), ConsistentRead=True).get("Item")
        return self._req_view(item) if item else None

    def req_list(self) -> list:
        """Moi yeu cau (ca da dong, giu 7 ngay). Doc het moi trang: id ngau nhien nen yeu cau dang cho co the
        nam o bat ky trang nao."""
        from boto3.dynamodb.conditions import Key
        kwargs = {"IndexName": "by_type", "KeyConditionExpression": Key("record_type").eq(self.REQ_TYPE)}
        items = []
        while True:
            res = self._table.query(**kwargs)
            items.extend(res.get("Items", []))
            if "LastEvaluatedKey" not in res:
                return [self._req_view(i) for i in items]
            kwargs["ExclusiveStartKey"] = res["LastEvaluatedKey"]

    def _update_if_pending(self, request_id: str, expression: str, values: dict) -> Optional[dict]:
        """UpdateItem chi khi yeu cau con 'pending'. Tra ve thuoc tinh moi, hoac None neu yeu cau da dong."""
        try:
            res = self._table.update_item(
                Key=self._req_key(request_id), UpdateExpression=expression,
                ConditionExpression="#s = :pending", ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={**values, ":pending": "pending"}, ReturnValues="ALL_NEW")
        except Exception as exc:
            if self._conditional_failed(exc):
                return None
            raise
        return res["Attributes"]

    def req_add_approval(self, request_id: str, principal: str) -> Optional[list]:
        attrs = self._update_if_pending(request_id, "ADD approvals :p", {":p": {principal}})
        return sorted(attrs["approvals"]) if attrs is not None else None

    def req_finish(self, request_id: str, status: str) -> bool:
        return self._update_if_pending(request_id, "SET #s = :new", {":new": status}) is not None


# ------------------------------------------------------------- governance
from caller_auth import cognito_principal  # noqa: E402  (mot dinh nghia chung cho moi Lambda)


def principal_name(principal: str) -> str:
    """'cognito:a@x.co' -> 'a@x.co', 'local:admin' -> 'admin'."""
    return principal.split(":", 1)[1]


class Governance:
    def __init__(self, store, identity=None, clock: Callable[[], float] = time.time,
                 local_principal: str = "local:admin"):
        self._store, self._identity, self._clock = store, identity, clock
        self._local_principal = local_principal

    # ------------------------------------------------------------- PIN
    def has_pin(self, principal: str) -> bool:
        return self._store.pin_get(principal) is not None

    def set_pin(self, principal: str, pin) -> None:
        if is_weak_pin(pin):
            raise WeakPin()
        salt = secrets.token_bytes(16)
        if not self._store.pin_create(principal, _hash_pin(pin, salt), salt.hex()):
            raise PinExists()

    def check_pin(self, principal: str, pin) -> None:
        """Dung -> xoa bo dem. Sai -> WrongPin; lan sai thu PIN_MAX_FAILURES khoa PIN_LOCK_SECONDS giay."""
        rec = self._store.pin_get(principal)
        if not rec:
            raise WrongPin()
        if float(rec.get("locked_until", 0)) > self._clock():
            raise PinLocked()
        ok = isinstance(pin, str) and len(pin) <= 16 and hmac.compare_digest(
            _hash_pin(pin, bytes.fromhex(rec["salt"])), rec["hash"])
        if ok:
            if rec.get("failures"):
                self._store.pin_clear_failures(principal)
            return
        if self._store.pin_fail(principal) >= PIN_MAX_FAILURES:
            self._store.pin_lock(principal, self._clock() + PIN_LOCK_SECONDS)
            raise WrongPin(just_locked=True)
        raise WrongPin()

    def reset_pin(self, actor: str, username) -> str:
        """Admin `actor` xoa PIN cua mot admin Cognito khac (ca bo dem khoa). Tra ve email nguoi duoc dat lai.
        PIN cua admin noi bo chi dat lai bang AWS CLI (xoa ban ghi ADMIN_PIN#local:<user>)."""
        directory = self._directory()
        self._ensure_local_allowed(actor, directory)
        target = directory["users"].get(username) if isinstance(username, str) else None
        if not target or target["role"] != "admin":
            raise InvalidTarget()
        principal = cognito_principal(target["email"])
        if principal == actor:
            raise SelfAction()
        self._store.pin_delete(principal)
        return target["email"]

    @property
    def local_principal(self) -> str:
        return self._local_principal

    def ensure_may_manage_viewers(self, actor: str) -> None:
        """Duyet / thu hoi Nguoi xem: admin Cognito, hoac admin noi bo trong che do khoi tao (quyet dinh Q2 b
        ngay 12/11: may bi chiem gia danh admin noi bo khong tu duyet duoc tai khoan de doc du lieu)."""
        directory = self._directory()
        self._ensure_local_allowed(actor, directory)
        if not _is_local(actor) and actor not in directory["admins"]:
            raise NotAdmin()

    def _ensure_local_allowed(self, actor: str, directory: dict) -> None:
        if _is_local(actor) and not directory["bootstrap"]:
            raise LocalAdminRestricted()

    # ----------------------------------------------------- danh ba admin
    def _directory(self) -> dict:
        """Anh chup danh ba tu Cognito: users (username -> email, role), admins (principal), bootstrap."""
        if self._identity is None:
            raise RequestNotFound()
        users = self._identity.list_users()
        by_username = {}
        for bucket, role in (("pending", "pending"), ("viewers", "viewer"), ("admins", "admin")):
            for u in users.get(bucket, []):
                by_username[u["username"]] = {"email": u["email"], "role": role}
        admins = {cognito_principal(u["email"]) for u in users.get("admins", [])}
        return {"users": by_username, "admins": admins, "bootstrap": len(admins) < MIN_ADMINS}

    def _ballot(self, directory: dict, req: dict) -> tuple:
        """(nguoi duoc bo phieu, so phieu can co). Nguoi bi tac dong khong bo phieu nhung van duoc tinh vao
        tong so admin khi lay da so (quyet dinh A1: 4 admin -> 3 phieu, ke ca khi ha mot nguoi)."""
        electorate = set(directory["admins"])
        if directory["bootstrap"]:
            electorate.add(self._local_principal)
        voters = electorate - {cognito_principal(req["target_email"])}
        return voters, required_approvals(req["action"], len(electorate))

    def summary(self) -> dict:
        """Hien ca khi muc Phan quyen dang khoa: canh bao do khi duoi 2 admin."""
        if self._identity is None:
            return {"admin_count": 0, "bootstrap": True}
        directory = self._directory()
        return {"admin_count": len(directory["admins"]), "bootstrap": directory["bootstrap"]}

    def pending_requests(self) -> list:
        if self._identity is None:
            return []
        directory, now = self._directory(), self._clock()
        out = []
        for req in self._store.req_list():
            if req["status"] == "pending" and req["created_at"] + REQUEST_TTL_SECONDS > now:
                _, needed = self._ballot(directory, req)
                out.append({**self._outcome(req), "initiator": principal_name(req["initiator"]),
                            "approvals": len(req["approvals"]), "needed": needed, "created_at": req["created_at"],
                            "expires_at": req["created_at"] + REQUEST_TTL_SECONDS})
        return sorted(out, key=lambda r: r["created_at"])

    # ------------------------------------------------------- yeu cau
    def _check_target(self, directory: dict, initiator: str, action: str, target: dict) -> None:
        reduces_admins = target["role"] == "admin" and action in ("demote", "disable")
        if action in ("demote", "disable") and cognito_principal(target["email"]) == initiator:
            raise SelfAction()
        if (action == "promote" and target["role"] != "viewer") or (action == "demote" and target["role"] != "admin"):
            raise InvalidTarget()
        if reduces_admins and len(directory["admins"]) - 1 < MIN_ADMINS:
            raise MinAdmins()

    def _eligible_voter(self, principal: str, directory: dict, req: dict) -> tuple:
        if _is_local(principal) and not directory["bootstrap"]:
            raise LocalAdminNoVote()
        voters, needed = self._ballot(directory, req)
        if principal not in voters:
            raise NotAVoter()
        return voters, needed

    def _bootstrap_promotion(self, directory: dict, req: dict, principal: str) -> bool:
        """Che do khoi tao: admin noi bo tu minh nang mot Nguoi xem len Quan tri."""
        return directory["bootstrap"] and req["action"] == "promote" and _is_local(principal)

    def create_request(self, initiator: str, action, username) -> dict:
        if action not in ACTIONS or not isinstance(username, str) or not username:
            raise InvalidRequest()
        directory = self._directory()
        target = directory["users"].get(username)
        if _is_local(initiator) and not directory["bootstrap"]:
            raise LocalAdminNoVote()
        if not target:
            raise InvalidTarget()
        self._check_target(directory, initiator, action, target)
        req = {"id": secrets.token_urlsafe(12), "action": action, "target_username": username,
               "target_email": target["email"], "initiator": initiator, "approvals": [initiator],
               "status": "pending", "created_at": self._clock()}
        voters, needed = self._eligible_voter(initiator, directory, req)
        bootstrap = self._bootstrap_promotion(directory, req, initiator)
        if not bootstrap and needed > len(voters):
            raise NotEnoughAdmins()
        self._store.req_put(req)
        if bootstrap:
            return self._execute(req, bootstrap=True)
        return {"status": "pending", **self._outcome(req)}

    def vote(self, voter: str, request_id, approve: bool) -> dict:
        req = self._store.req_get(request_id) if isinstance(request_id, str) else None
        if not req:
            raise RequestNotFound()
        if req["status"] != "pending":
            raise RequestClosed()
        if req["created_at"] + REQUEST_TTL_SECONDS < self._clock():
            with self._execution_lock():
                self._store.req_finish(request_id, "expired")
            raise RequestExpired()
        directory = self._directory()
        voters, needed = self._eligible_voter(voter, directory, req)
        if not approve:
            # Cung khoa voi _execute: khong dong yeu cau giua luc mot worker khac dang goi Cognito cho no.
            with self._execution_lock():
                if not self._store.req_finish(request_id, "rejected"):
                    raise RequestClosed()
            return {"status": "rejected", **self._outcome(req)}
        bootstrap = self._bootstrap_promotion(directory, req, voter)
        if voter in req["approvals"] and not bootstrap and len(set(req["approvals"]) & voters) < needed:
            raise AlreadyVoted()  # da du phieu ma lan truoc Cognito loi -> cho bam lai de thu lai
        approvals = self._store.req_add_approval(request_id, voter)
        if approvals is None:
            raise RequestClosed()
        req["approvals"] = approvals
        if bootstrap or len(set(approvals) & voters) >= needed:
            return self._execute(req, bootstrap=bootstrap)
        return {"status": "pending", **self._outcome(req)}

    def _execute(self, req: dict, bootstrap: bool) -> dict:
        """Thuc thi duoi khoa dung chung: moi lan chi mot thao tac, kiem tra lai danh ba ngay truoc khi goi
        Cognito (hai yeu cau ha admin chay song song khong the cung thay 3 admin). Chi danh dau 'executed'
        SAU KHI Cognito thanh cong; Cognito loi -> yeu cau van cho (ChangeFailed)."""
        with self._execution_lock():
            current = self._store.req_get(req["id"])
            if not current or current["status"] != "pending":
                raise RequestClosed()
            directory = self._directory()
            target = directory["users"].get(req["target_username"])
            if not target:
                self._store.req_finish(req["id"], "failed")
                raise ExecutionFailed()
            self._check_target(directory, req["initiator"], req["action"], target)
            outcome = {"bootstrap": bootstrap, **self._outcome(req)}
            try:
                changed = getattr(self._identity, req["action"])(req["target_username"])
            except Exception:
                raise ChangeFailed({"status": "failed", **outcome}) from None
            if not changed:
                self._store.req_finish(req["id"], "failed")
                raise ExecutionFailed()
            self._store.req_finish(req["id"], "executed")
            return {"status": "executed", **outcome}

    @contextlib.contextmanager
    def _execution_lock(self):
        """Khoa dung chung moi worker cho moi lan dong yeu cau (thuc thi, tu choi, het han). Dang co nguoi giu -> Busy.
        Moi lan lay khoa co ma chu rieng: worker cham qua han khong mo khoa cua worker lay khoa sau no."""
        owner = secrets.token_hex(8)
        if not self._store.lock_acquire(EXECUTE_LOCK, self._clock(), EXECUTE_LOCK_SECONDS, owner):
            raise Busy()
        try:
            yield
        finally:
            self._store.lock_release(EXECUTE_LOCK, owner)

    @staticmethod
    def _outcome(req: dict) -> dict:
        return {"id": req["id"], "action": req["action"], "target_user": req["target_email"],
                "approvers": list(req["approvals"])}
