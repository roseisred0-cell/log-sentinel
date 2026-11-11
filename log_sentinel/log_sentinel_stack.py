import os
from pathlib import Path
from aws_cdk import (
    Annotations,
    Stack,
    Duration,
    RemovalPolicy,
    CfnOutput,
    aws_s3 as s3,
    aws_kms as kms,
    aws_dynamodb as dynamodb,
    aws_logs as logs,
    aws_logs_destinations as logs_destinations,
    aws_lambda as _lambda,
    aws_sns as sns,
    aws_sns_subscriptions as subs,
    aws_secretsmanager as secretsmanager,
    aws_cloudtrail as cloudtrail,
    aws_iam as iam,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_ec2 as ec2,
    aws_s3_assets as s3_assets,
    aws_kinesisfirehose as firehose,
    aws_cognito as cognito,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_events as events,
    aws_events_targets as events_targets,
    aws_budgets as budgets,
    aws_glue as glue,
    aws_athena as athena,
)
from constructs import Construct

from log_sentinel import cloudtrail_athena


ROOT_DIR = Path(__file__).resolve().parent.parent
WEBAPP_DIR = ROOT_DIR / "sample_app"

# Ten su kien CloudTrail duoc chuyen toi Detector. PHAI chua moi su kien ma lambda_src/detector.py co luat
# (tests/unit/test_stack_hardening.py kiem tra dieu nay): su kien khong nam o day se khong bao gio toi Lambda.
CLOUDTRAIL_WATCHED_EVENTS = (
    "ConsoleLogin",
    "DeactivateMFADevice", "DeleteVirtualMFADevice",
    "StopLogging", "DeleteTrail",
    "ScheduleKeyDeletion", "DisableKey",
    "CreateAccessKey",
    "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
    "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
    "CreatePolicyVersion", "UpdateAssumeRolePolicy",
    "CreateLoginProfile", "UpdateLoginProfile",
    "AddUserToGroup",
)


class LogSentinelConfig:
    """Hang so khong nhay cam. Gia tri rieng tu (email, IP) lay tu context/env, KHONG commit vao Git:

        cdk deploy -c alert_email=soc@example.com -c admin_cidr=203.0.113.10/32
    """
    PROJECT_NAME = "LogSentinel"
    # 30 ngay: khop voi log CloudTrail tren S3 (S3_EXPIRATION_DAYS). Phi luu tru CloudWatch rat nho so voi phi ghi,
    # nen giu lau hon gan nhu khong ton them, ma tan cong phat hien muon van con log de dieu tra.
    LOG_RETENTION_DAYS = logs.RetentionDays.ONE_MONTH
    S3_EXPIRATION_DAYS = 30

    def __init__(self, scope: Construct):
        def ctx(key: str, env_key: str, default: str = "") -> str:
            return str(scope.node.try_get_context(key) or os.environ.get(env_key) or default).strip()

        self.alert_email = ctx("alert_email", "LOGSENTINEL_ALERT_EMAIL")
        # IP quan tri: khong bao gio bi SOAR khoa (chong tu khoa chinh minh khi demo).
        self.admin_cidr = ctx("admin_cidr", "LOGSENTINEL_ADMIN_CIDR")
        # Ai duoc goi HTTPS 443 toi may muc tieu (mac dinh Internet de demo tan cong).
        self.ingress_cidr = ctx("ingress_cidr", "LOGSENTINEL_INGRESS_CIDR", "0.0.0.0/0")
        # Tran so Lambda chay song song (chong Denial of Wallet khi bi flood log). Mac dinh TAT vi
        # tai khoan moi thuong chi co quota 10 concurrency, khong du de "reserve" -> deploy se loi.
        # Bat: cdk deploy -c detector_max_concurrency=5  (can quota tai khoan >= 105)
        raw = ctx("detector_max_concurrency", "LOGSENTINEL_DETECTOR_MAX_CONCURRENCY")
        self.detector_max_concurrency = int(raw) if raw.isdigit() and int(raw) > 0 else None
        # Luu tru log app xuong S3 qua Firehose. Mac dinh TAT vi tai khoan moi/chua kich hoat day du se
        # bi loi "The AWS Access Key Id needs a subscription for the service (Firehose)" luc deploy.
        # Bat: cdk deploy -c enable_app_log_archive=true  (sau khi tai khoan dung duoc Firehose)
        self.enable_app_log_archive = ctx(
            "enable_app_log_archive", "LOGSENTINEL_ENABLE_APP_LOG_ARCHIVE").lower() in ("1", "true", "yes")
        # Canh bao chi phi (AWS Budgets) gui toi alert_email khi chi tieu thuc te cua TAI KHOAN dat 80% va khi
        # du bao vuot 100% muc nay. Bao ve vi tien khi bi tan cong lam phat sinh Lambda/DynamoDB/WAF.
        # Tat: cdk deploy -c monthly_budget_usd=0
        raw = ctx("monthly_budget_usd", "LOGSENTINEL_MONTHLY_BUDGET_USD", "20")
        self.monthly_budget_usd = int(raw) if raw.isdigit() else 0


def edge_enabled(scope: Construct) -> bool:
    """cdk deploy --all -c enable_edge=true : dat CloudFront + WAF truoc may (xem log_sentinel/edge_stack.py)."""
    raw = scope.node.try_get_context("enable_edge") or os.environ.get("LOGSENTINEL_ENABLE_EDGE") or ""
    return str(raw).strip().lower() in ("1", "true", "yes")


def console_cidrs(scope: Construct) -> list:
    """-c console_cidrs=203.0.113.0/24,198.51.100.7/32 : chi cac dai nay vao duoc Console (luat WAF, che do edge)."""
    raw = scope.node.try_get_context("console_cidrs") or os.environ.get("LOGSENTINEL_CONSOLE_CIDRS") or ""
    return [c.strip() for c in str(raw).split(",") if c.strip()]


class LogSentinelStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, edge=None, **kwargs) -> None:
        """`edge`: LogSentinelEdgeStack (us-east-1) hoac None. Co edge -> nguoi dung vao qua CloudFront + WAF,
        may chi nhan ket noi tu CloudFront. Khong co -> Internet vao thang may qua TLS tu ky (lab)."""
        super().__init__(scope, construct_id, **kwargs)
        self.cfg = LogSentinelConfig(self)
        self.edge = edge

        self._build_security_and_storage()
        self._build_log_ingestion()
        self._build_log_analytics()
        self._build_detection_and_alerting()
        self._build_user_directory()
        self._build_target_ec2_vm()
        self._build_edge_distribution()
        self._build_alarms()
        self._build_cost_guard()
        self._build_monitoring_dashboard()
        self._export_outputs()

    def _build_security_and_storage(self) -> None:
        self.kms_key = kms.Key(
            self, "LogSentinelKmsKey",
            enable_key_rotation=True,
            description="LogSentinel CMK: ma hoa IncidentTable va CloudTrail log tren S3",
            removal_policy=RemovalPolicy.DESTROY
        )
        # CloudTrail can quyen nay de ma hoa log bang CMK (neu thieu: InsufficientEncryptionPolicyException).
        trail_arn_pattern = f"arn:{self.partition}:cloudtrail:*:{self.account}:trail/*"
        self.kms_key.add_to_resource_policy(iam.PolicyStatement(
            sid="AllowCloudTrailEncryptLogs",
            principals=[iam.ServicePrincipal("cloudtrail.amazonaws.com")],
            actions=["kms:GenerateDataKey*"],
            resources=["*"],
            conditions={"StringLike": {"kms:EncryptionContext:aws:cloudtrail:arn": trail_arn_pattern}},
        ))
        self.kms_key.add_to_resource_policy(iam.PolicyStatement(
            sid="AllowCloudTrailDescribeKey",
            principals=[iam.ServicePrincipal("cloudtrail.amazonaws.com")],
            actions=["kms:DescribeKey"],
            resources=["*"],
        ))

        self.archive_bucket = s3.Bucket(
            self, "LogArchiveBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            lifecycle_rules=[
                s3.LifecycleRule(expiration=Duration.days(LogSentinelConfig.S3_EXPIRATION_DAYS))
            ]
        )

        self.incident_table = dynamodb.Table(
            self, "IncidentTable",
            partition_key=dynamodb.Attribute(name="incident_id", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="timestamp", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=self.kms_key,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.DESTROY
        )
        # GSI thua (sparse): chi item co record_type (INCIDENT / BLOCK) moi vao index.
        # SOC Console dung Query tren index nay thay vi Scan ca bang.
        self.incident_table.add_global_secondary_index(
            index_name="by_type",
            partition_key=dynamodb.Attribute(name="record_type", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="timestamp", type=dynamodb.AttributeType.STRING),
            projection_type=dynamodb.ProjectionType.ALL,
        )

        self.telegram_secret = secretsmanager.Secret(
            self, "TelegramBotSecret",
            secret_name="logsentinel/telegram_credentials",
            description="Luu BOT_TOKEN va CHAT_ID cho Telegram",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                secret_string_template='{"BOT_TOKEN": "REPLACE_ME", "CHAT_ID": "REPLACE_ME"}',
                generate_string_key="dummy"
            ),
            removal_policy=RemovalPolicy.DESTROY
        )

    def _build_log_ingestion(self) -> None:
        self.app_log_group = logs.LogGroup(
            self, "SampleAppLogGroup",
            log_group_name="/logsentinel/sample-app",
            retention=LogSentinelConfig.LOG_RETENTION_DAYS,
            removal_policy=RemovalPolicy.DESTROY
        )

        self.trail_log_group = logs.LogGroup(
            self, "CloudTrailLogGroup",
            log_group_name="/logsentinel/cloudtrail",
            retention=LogSentinelConfig.LOG_RETENTION_DAYS,
            removal_policy=RemovalPolicy.DESTROY
        )

        self.trail = cloudtrail.Trail(
            self, "AccountActivityTrail",
            bucket=self.archive_bucket,
            send_to_cloud_watch_logs=True,
            cloud_watch_log_group=self.trail_log_group,
            cloud_watch_logs_retention=LogSentinelConfig.LOG_RETENTION_DAYS,
            # Su kien IAM/ConsoleLogin la su kien toan cau (ghi o us-east-1): phai bat ca 2 co
            # thi luat CONSOLE_LOGIN_NO_MFA va 3 luat IAM moi nhan duoc log tai Singapore.
            is_multi_region_trail=True,
            include_global_service_events=True,
            enable_file_validation=True,
            encryption_key=self.kms_key,
        )

        if self.cfg.enable_app_log_archive:
            self._archive_app_logs_to_s3()
        else:
            Annotations.of(self).add_warning(
                "Log app KHONG duoc archive xuong S3 (Firehose tat). Bat: cdk deploy -c enable_app_log_archive=true")

    def _build_log_analytics(self) -> None:
        """Athena tren log CloudTrail da luu o S3: truy van SQL cho dieu tra va so lieu bao cao (khong can may chu)."""
        self.analytics_db = glue.CfnDatabase(
            self, "AnalyticsDatabase",
            catalog_id=self.account,
            database_input={"name": "logsentinel", "description": "LogSentinel: log luu tru de truy van bang Athena"},
        )
        self.cloudtrail_table = glue.CfnTable(
            self, "CloudTrailAthenaTable",
            catalog_id=self.account,
            database_name="logsentinel",
            table_input=cloudtrail_athena.table_input(self.archive_bucket.bucket_name, self.account),
        )
        self.cloudtrail_table.node.add_dependency(self.analytics_db)

        # Workgroup rieng: ket qua nam trong bucket luu tru (tu xoa sau 30 ngay cung voi log), va moi truy van
        # bi chan o 1 GB du lieu quet - mot cau SQL quen dieu kien ngay khong the dot tien.
        self.athena_workgroup = athena.CfnWorkGroup(
            self, "AthenaWorkGroup",
            name="logsentinel",
            description="Truy van log LogSentinel",
            recursive_delete_option=True,
            work_group_configuration={
                "enforceWorkGroupConfiguration": True,
                "bytesScannedCutoffPerQuery": 1024 ** 3,
                "publishCloudWatchMetricsEnabled": False,
                "resultConfiguration": {
                    "outputLocation": f"s3://{self.archive_bucket.bucket_name}/athena-results/",
                    "encryptionConfiguration": {"encryptionOption": "SSE_S3"},
                },
            },
        )

        for index, (name, description, sql) in enumerate(cloudtrail_athena.NAMED_QUERIES):
            query = athena.CfnNamedQuery(
                self, f"AthenaQuery{index}",
                name=name, description=description, database="logsentinel",
                work_group="logsentinel", query_string=sql,
            )
            query.node.add_dependency(self.athena_workgroup)
            query.node.add_dependency(self.cloudtrail_table)

        # Quyen cho nguoi lam bao cao / dieu tra: chay truy van trong workgroup nay va DOC log. Khong sua, khong xoa.
        # Gan tay cho IAM user can dung:  aws iam attach-user-policy --user-name <user> --policy-arn <AthenaAnalystPolicyArn>
        bucket_arn = self.archive_bucket.bucket_arn
        glue_arn = f"arn:{self.partition}:glue:{self.region}:{self.account}"
        self.athena_analyst_policy = iam.ManagedPolicy(
            self, "AthenaAnalystPolicy",
            managed_policy_name="LogSentinel-AthenaAnalyst",
            description="Chay truy van Athena tren log LogSentinel, chi doc",
            statements=[
                iam.PolicyStatement(
                    actions=["athena:StartQueryExecution", "athena:StopQueryExecution", "athena:GetQueryExecution",
                             "athena:GetQueryResults", "athena:ListQueryExecutions", "athena:GetWorkGroup",
                             "athena:ListNamedQueries", "athena:GetNamedQuery", "athena:BatchGetNamedQuery"],
                    resources=[f"arn:{self.partition}:athena:{self.region}:{self.account}:workgroup/logsentinel"]),
                iam.PolicyStatement(
                    actions=["glue:GetDatabase", "glue:GetTable", "glue:GetTables", "glue:GetPartitions"],
                    resources=[f"{glue_arn}:catalog", f"{glue_arn}:database/logsentinel",
                               f"{glue_arn}:table/logsentinel/*"]),
                iam.PolicyStatement(
                    actions=["s3:GetBucketLocation", "s3:ListBucket"], resources=[bucket_arn]),
                iam.PolicyStatement(
                    actions=["s3:GetObject"],
                    resources=[f"{bucket_arn}/AWSLogs/*", f"{bucket_arn}/athena-results/*"]),
                iam.PolicyStatement(
                    actions=["s3:PutObject", "s3:AbortMultipartUpload"],
                    resources=[f"{bucket_arn}/athena-results/*"]),
                # Log CloudTrail tren S3 duoc ma hoa bang CMK.
                iam.PolicyStatement(actions=["kms:Decrypt"], resources=[self.kms_key.key_arn]),
            ],
        )
        CfnOutput(self, "AthenaWorkGroupName", value="logsentinel",
                  description="Athena: chon workgroup nay, database logsentinel, bang cloudtrail_logs")
        CfnOutput(self, "AthenaAnalystPolicyArn", value=self.athena_analyst_policy.managed_policy_arn,
                  description="Gan cho IAM user lam bao cao: aws iam attach-user-policy --user-name <user> --policy-arn <arn>")

    def _archive_app_logs_to_s3(self) -> None:
        """Buoc 3 ke hoach: log ung dung -> Firehose -> S3 (prefix app-logs/), luu 30 ngay de dieu tra."""
        delivery_role = iam.Role(
            self, "AppLogFirehoseRole",
            assumed_by=iam.ServicePrincipal("firehose.amazonaws.com"),
        )
        self.archive_bucket.grant_write(delivery_role)

        self.app_log_stream = firehose.CfnDeliveryStream(
            self, "AppLogArchiveStream",
            delivery_stream_type="DirectPut",
            delivery_stream_encryption_configuration_input=(
                firehose.CfnDeliveryStream.DeliveryStreamEncryptionConfigurationInputProperty(
                    key_type="AWS_OWNED_CMK")),
            extended_s3_destination_configuration=firehose.CfnDeliveryStream.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=self.archive_bucket.bucket_arn,
                role_arn=delivery_role.role_arn,
                prefix="app-logs/!{timestamp:yyyy/MM/dd}/",
                error_output_prefix="app-logs-errors/!{firehose:error-output-type}/!{timestamp:yyyy/MM/dd}/",
                buffering_hints=firehose.CfnDeliveryStream.BufferingHintsProperty(
                    interval_in_seconds=300, size_in_m_bs=5),
                # CloudWatch Logs da gzip san tung ban ghi -> khong nen lan 2.
                compression_format="UNCOMPRESSED",
            ),
        )
        self.app_log_stream.node.add_dependency(delivery_role)

        logs_to_firehose_role = iam.Role(
            self, "AppLogSubscriptionRole",
            assumed_by=iam.ServicePrincipal("logs.amazonaws.com"),
        )
        logs_to_firehose_role.add_to_policy(iam.PolicyStatement(
            actions=["firehose:PutRecord", "firehose:PutRecordBatch"],
            resources=[self.app_log_stream.attr_arn],
        ))
        archive_filter = logs.CfnSubscriptionFilter(
            self, "AppLogArchiveSubscription",
            log_group_name=self.app_log_group.log_group_name,
            filter_pattern="",
            destination_arn=self.app_log_stream.attr_arn,
            role_arn=logs_to_firehose_role.role_arn,
        )
        archive_filter.node.add_dependency(logs_to_firehose_role)

    def _build_detection_and_alerting(self) -> None:
        self.alert_topic = sns.Topic(self, "SecurityAlertTopic", display_name="LogSentinel Alerts")
        if self.cfg.alert_email:
            self.alert_topic.add_subscription(subs.EmailSubscription(self.cfg.alert_email))
        else:
            Annotations.of(self).add_warning(
                "Chua co alert_email: SNS se khong gui email. Dung: cdk deploy -c alert_email=<email>")

        if not self.cfg.admin_cidr:
            Annotations.of(self).add_warning(
                "Chua co admin_cidr: IP cua chinh ban co the bi SOAR khoa 24h khi go sai mat khau/OTP. "
                "Dung: cdk deploy -c admin_cidr=<ip-cua-ban>/32")

        self.detector_log_group = logs.LogGroup(
            self, "DetectorLogGroup",
            log_group_name="/logsentinel/detector",
            retention=LogSentinelConfig.LOG_RETENTION_DAYS,
            removal_policy=RemovalPolicy.DESTROY
        )

        self.detector_lambda = _lambda.Function(
            self, "AnomalyDetectorLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="detector.handler",
            code=_lambda.Code.from_asset("lambda_src"),
            timeout=Duration.seconds(30),
            memory_size=256,
            log_group=self.detector_log_group,
            reserved_concurrent_executions=self.cfg.detector_max_concurrency,
            environment={
                "INCIDENT_TABLE": self.incident_table.table_name,
                "SNS_TOPIC_ARN": self.alert_topic.topic_arn,
                "SECRET_ARN": self.telegram_secret.secret_arn,
                "BLOCK_ALLOWLIST_CIDRS": self.cfg.admin_cidr,
            }
        )

        # Least privilege: detector chi ghi (PutItem/UpdateItem), khong Scan/Delete duoc bang su co.
        self.detector_lambda.add_to_role_policy(iam.PolicyStatement(
            actions=["dynamodb:PutItem", "dynamodb:UpdateItem"],
            resources=[self.incident_table.table_arn],
        ))
        self.alert_topic.grant_publish(self.detector_lambda)
        self.telegram_secret.grant_read(self.detector_lambda)
        self.kms_key.grant_encrypt_decrypt(self.detector_lambda)

        logs.SubscriptionFilter(
            self, "AppLogSubscription",
            log_group=self.app_log_group,
            destination=logs_destinations.LambdaDestination(self.detector_lambda),
            filter_pattern=logs.FilterPattern.all_events()
        )

        logs.SubscriptionFilter(
            self, "CloudTrailSubscription",
            log_group=self.trail_log_group,
            destination=logs_destinations.LambdaDestination(self.detector_lambda),
            filter_pattern=logs.FilterPattern.any_term(*CLOUDTRAIL_WATCHED_EVENTS)
        )

    def _build_user_directory(self) -> None:
        """Cognito cho SOC Console: tu dang ky + xac nhan email, 2FA TOTP TUY CHON (nguoi dung tu bat/tat).
        Vai tro = nhom Cognito. Nguoi moi dang ky khong thuoc nhom nao -> 'cho duyet', chua xem duoc du lieu."""
        self.user_pool = cognito.UserPool(
            self, "ConsoleUserPool",
            user_pool_name="LogSentinel-Console",
            self_sign_up_enabled=True,
            sign_in_aliases=cognito.SignInAliases(email=True),
            auto_verify=cognito.AutoVerifiedAttrs(email=True),
            standard_attributes=cognito.StandardAttributes(
                email=cognito.StandardAttribute(required=True, mutable=False)),
            password_policy=cognito.PasswordPolicy(
                min_length=8, require_lowercase=True, require_uppercase=True,
                require_digits=True, require_symbols=False),
            mfa=cognito.Mfa.OPTIONAL,
            mfa_second_factor=cognito.MfaSecondFactor(sms=False, otp=True),
            account_recovery=cognito.AccountRecovery.EMAIL_ONLY,
            removal_policy=RemovalPolicy.DESTROY,
        )
        # Client cong khai (khong secret): web app goi USER_PASSWORD_AUTH tu may chu qua TLS.
        self.user_pool_client = self.user_pool.add_client(
            "ConsoleWebClient",
            generate_secret=False,
            auth_flows=cognito.AuthFlow(user_password=True),
            prevent_user_existence_errors=True,
            enable_token_revocation=True,
            access_token_validity=Duration.minutes(30),
            id_token_validity=Duration.minutes(30),
            refresh_token_validity=Duration.hours(12),
        )
        for logical_id, group, text in (
            ("SocViewersGroup", "soc-viewers", "Duoc xem su co va IP bi khoa (chi doc)"),
            ("SocAdminsGroup", "soc-admins", "Xem + go khoa IP + duyet nguoi dung"),
        ):
            cognito.CfnUserPoolGroup(self, logical_id, user_pool_id=self.user_pool.user_pool_id,
                                     group_name=group, description=text)

    def _build_target_ec2_vm(self) -> None:
        """Nginx TLS 443 -> Gunicorn 127.0.0.1:8080. Code + cau hinh ship bang S3 asset (khong nhoi vao UserData)."""
        vpc = ec2.Vpc.from_lookup(self, "DefaultVPC", is_default=True)

        self.vm_sg = ec2.SecurityGroup(
            self, "TargetVmSecurityGroup",
            vpc=vpc,
            description="LogSentinel target: chi 1 cong vao qua Nginx. 8080 chi bind loopback.",
            allow_all_outbound=True
        )
        if self.edge:
            # Chi may chu CloudFront ket noi duoc: IP that cua may khong con la mat tan cong tu Internet.
            # (Nginx con kiem tra them header bi mat, vi distribution cua nguoi khac cung nam trong dai IP nay.)
            cloudfront_ips = ec2.PrefixList.from_lookup(
                self, "CloudFrontOriginFacing", prefix_list_name="com.amazonaws.global.cloudfront.origin-facing")
            self.vm_sg.add_ingress_rule(ec2.Peer.prefix_list(cloudfront_ips.prefix_list_id), ec2.Port.tcp(80),
                                        "HTTP chi tu CloudFront")
            self.origin_secret = secretsmanager.Secret(
                self, "OriginVerifySecret",
                description="Header bi mat CloudFront gui cho Nginx (X-Origin-Verify)",
                generate_secret_string=secretsmanager.SecretStringGenerator(
                    exclude_punctuation=True, include_space=False, password_length=48),
                removal_policy=RemovalPolicy.DESTROY,
            )
        else:
            self.vm_sg.add_ingress_rule(ec2.Peer.ipv4(self.cfg.ingress_cidr), ec2.Port.tcp(443), "HTTPS via Nginx")

        vm_role = iam.Role(
            self, "TargetVmRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            # SSM Session Manager thay cho SSH: khong mo cong 22.
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore")]
        )
        # Least privilege (thay CloudWatchAgentServerPolicy - policy do cho phep ghi vao MOI log group,
        # ke ca /logsentinel/cloudtrail -> may bi chiem co the bom su kien CloudTrail gia).
        self.app_log_group.grant_write(vm_role)
        vm_role.add_to_policy(iam.PolicyStatement(
            actions=["logs:DescribeLogStreams"],
            resources=[self.app_log_group.log_group_arn],
        ))
        # Web app: GetItem de kiem tra BLOCKED_IP#<ip>; SOC Console: Query tren GSI by_type (khong Scan).
        vm_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:GetItem"],
            resources=[self.incident_table.table_arn],
        ))
        vm_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:Query"],
            resources=[f"{self.incident_table.table_arn}/index/by_type"],
        ))
        # Go khoa tu Console: chi xoa duoc item BLOCKED_IP#..., KHONG xoa duoc ban ghi su co (bang chung).
        vm_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:DeleteItem"],
            resources=[self.incident_table.table_arn],
            conditions={"ForAllValues:StringLike": {"dynamodb:LeadingKeys": ["BLOCKED_IP#*"]}},
        ))
        # Dang xuat = ghi REVOKED_SESSION#<sid> de cookie bi danh cap khong dung lai duoc. Chi dung khoa nay.
        vm_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:PutItem"],
            resources=[self.incident_table.table_arn],
            conditions={"ForAllValues:StringLike": {"dynamodb:LeadingKeys": ["REVOKED_SESSION#*"]}},
        ))
        self.kms_key.grant_encrypt_decrypt(vm_role)
        if self.edge:
            self.origin_secret.grant_read(vm_role)
        # Duyet nguoi dung tren SOC Console: chi tren dung user pool nay. Dang ky/dang nhap la API cong khai
        # (khong can quyen IAM). Luu y: Console chay chung may voi app muc tieu -> may bi chiem co the tu duyet
        # nguoi dung vao nhom viewer (xem Gioi han trong docs/SECURITY_REVIEW.md).
        vm_role.add_to_policy(iam.PolicyStatement(
            actions=["cognito-idp:ListUsers", "cognito-idp:ListUsersInGroup",
                     "cognito-idp:AdminAddUserToGroup", "cognito-idp:AdminRemoveUserFromGroup"],
            resources=[self.user_pool.user_pool_arn],
        ))

        webapp_asset = s3_assets.Asset(
            self, "WebAppAsset",
            path=str(WEBAPP_DIR),
            exclude=["__pycache__", "*.pyc", ".pytest_cache"],
        )
        webapp_asset.grant_read(vm_role)

        user_data = ec2.UserData.for_linux()
        user_data.add_commands("set -euxo pipefail", "dnf install -y unzip")
        zip_path = user_data.add_s3_download_command(
            bucket=webapp_asset.bucket,
            bucket_key=webapp_asset.s3_object_key,
            local_file="/tmp/webapp.zip",
        )
        # Chi ARN cua bi mat nam trong UserData; gia tri do bootstrap.sh tu lay bang role cua may.
        edge_env = f"EDGE_MODE=true ORIGIN_SECRET_ARN={self.origin_secret.secret_arn} " if self.edge else ""
        user_data.add_commands(
            "mkdir -p /opt/logsentinel/app",
            f"unzip -o {zip_path} -d /opt/logsentinel/app",
            f"INCIDENT_TABLE={self.incident_table.table_name} AWS_REGION={self.region} "
            f"COGNITO_USER_POOL_ID={self.user_pool.user_pool_id} "
            f"COGNITO_CLIENT_ID={self.user_pool_client.user_pool_client_id} "
            f"{edge_env}"
            "bash /opt/logsentinel/app/deploy/bootstrap.sh",
        )

        self.target_vm = ec2.Instance(
            self, "TargetWebServerVM",
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
            machine_image=ec2.MachineImage.latest_amazon_linux2023(),
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            associate_public_ip_address=True,
            security_group=self.vm_sg,
            role=vm_role,
            user_data=user_data,
            # Doi code app -> doi hash asset -> thay may moi, tranh "deploy roi ma code cu van chay".
            user_data_causes_replacement=True,
            require_imdsv2=True,
            block_devices=[ec2.BlockDevice(
                device_name="/dev/xvda",
                volume=ec2.BlockDeviceVolume.ebs(8, encrypted=True, volume_type=ec2.EbsDeviceVolumeType.GP3),
            )],
        )

        CfnOutput(self, "TargetVmInstanceId", value=self.target_vm.instance_id,
                  description="Lay mat khau/TOTP: aws ssm start-session --target <id>, roi sudo cat /etc/logsentinel/webapp.env")

    def _build_edge_distribution(self) -> None:
        """
        Dia chi cong khai cua he thong. Che do edge: CloudFront (chung chi that, dia chi khong doi khi thay may)
        + WAF + dong bo IP bi khoa len WAF. Che do truc tiep: IP cong khai cua may, TLS tu ky.
        """
        if not self.edge:
            base_url = f"https://{self.target_vm.instance_public_ip}"
        else:
            self.distribution = cloudfront.Distribution(
                self, "EdgeDistribution",
                comment="LogSentinel edge: CloudFront + WAF truoc may web",
                default_behavior=cloudfront.BehaviorOptions(
                    origin=origins.HttpOrigin(
                        self.target_vm.instance_public_dns_name,
                        protocol_policy=cloudfront.OriginProtocolPolicy.HTTP_ONLY,
                        http_port=80,
                        # Nginx tu choi moi request thieu header nay.
                        custom_headers={"X-Origin-Verify": self.origin_secret.secret_value.unsafe_unwrap()},
                    ),
                    viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                    allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                    # Console va API la noi dung dong theo tung nguoi dung: khong cache, chuyen het cookie/header.
                    cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                    origin_request_policy=cloudfront.OriginRequestPolicy.ALL_VIEWER,
                ),
                web_acl_id=self.edge.web_acl.attr_arn,
                minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
                # IPv4 only: IP set cua WAF va moi luat theo IP trong he thong deu la IPv4.
                enable_ipv6=False,
                price_class=cloudfront.PriceClass.PRICE_CLASS_200,
            )
            base_url = f"https://{self.distribution.distribution_domain_name}"
            self._build_waf_sync()

        CfnOutput(self, "TargetVmAttackUrl", value=base_url)
        CfnOutput(self, "SocConsoleUrl", value=f"{base_url}/console",
                  description="Giao dien SOC Console cho khach hang (dang nhap mat khau + OTP)")

    def _build_waf_sync(self) -> None:
        """Moi phut: IP dang bi khoa trong DynamoDB -> IP set cua WAF (chan tai bien, truoc khi toi may)."""
        ip_set = self.edge.blocked_ip_set
        self.waf_sync_log_group = logs.LogGroup(
            self, "WafSyncLogGroup",
            log_group_name="/logsentinel/waf-sync",
            retention=LogSentinelConfig.LOG_RETENTION_DAYS,
            removal_policy=RemovalPolicy.DESTROY,
        )
        self.waf_sync_lambda = _lambda.Function(
            self, "WafSyncLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="waf_sync.handler",
            code=_lambda.Code.from_asset("lambda_src"),
            timeout=Duration.seconds(30),
            memory_size=256,
            log_group=self.waf_sync_log_group,
            environment={
                "INCIDENT_TABLE": self.incident_table.table_name,
                "WAF_IP_SET_NAME": ip_set.name,
                "WAF_IP_SET_ID": ip_set.attr_id,
            },
        )
        # Chi doc danh sach lenh khoa (GSI) va chi sua dung 1 IP set.
        self.waf_sync_lambda.add_to_role_policy(iam.PolicyStatement(
            actions=["dynamodb:Query"],
            resources=[f"{self.incident_table.table_arn}/index/by_type"],
        ))
        self.waf_sync_lambda.add_to_role_policy(iam.PolicyStatement(
            actions=["wafv2:GetIPSet", "wafv2:UpdateIPSet"],
            resources=[ip_set.attr_arn],
        ))
        self.kms_key.grant_decrypt(self.waf_sync_lambda)
        events.Rule(
            self, "WafSyncSchedule",
            schedule=events.Schedule.rate(Duration.minutes(1)),
            targets=[events_targets.LambdaFunction(self.waf_sync_lambda)],
        )

    def _build_cost_guard(self) -> None:
        """AWS Budgets: email khi chi tieu thang cua tai khoan sap vuot nguong (chong Denial of Wallet)."""
        if not (self.cfg.monthly_budget_usd and self.cfg.alert_email):
            if self.cfg.monthly_budget_usd:
                Annotations.of(self).add_warning("Khong tao canh bao chi phi vi chua co alert_email.")
            return
        subscriber = [{"subscriptionType": "EMAIL", "address": self.cfg.alert_email}]

        def notify(kind: str, threshold: int) -> dict:
            return {"notification": {"notificationType": kind, "comparisonOperator": "GREATER_THAN",
                                     "threshold": threshold, "thresholdType": "PERCENTAGE"},
                    "subscribers": subscriber}

        budgets.CfnBudget(
            self, "MonthlyCostBudget",
            budget={"budgetType": "COST", "timeUnit": "MONTHLY",
                    "budgetLimit": {"amount": self.cfg.monthly_budget_usd, "unit": "USD"}},
            notifications_with_subscribers=[notify("ACTUAL", 80), notify("FORECASTED", 100)],
        )

    def _build_alarms(self) -> None:
        """3 CloudWatch Alarm gui ve SNS: loi detector, su kien web nghiem trong, CloudTrail bi tat."""
        five_min = Duration.minutes(5)
        breach = cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD
        no_data = cloudwatch.TreatMissingData.NOT_BREACHING
        action = cw_actions.SnsAction(self.alert_topic)

        # 1. Detector Lambda bi loi: neu detector hong thi moi canh bao khac deu mat.
        self.detector_error_alarm = cloudwatch.Alarm(
            self, "DetectorErrorsAlarm",
            alarm_description="Detector Lambda bao loi: he thong phat hien co the dang mu.",
            metric=self.detector_lambda.metric_errors(period=five_min),
            threshold=1, evaluation_periods=1,
            comparison_operator=breach, treat_missing_data=no_data,
        )

        # 2. Su kien web nghiem trong (bypass 2FA, SQL injection) dem truc tiep tu log.
        self.critical_web_filter = logs.MetricFilter(
            self, "CriticalWebEventsFilter",
            log_group=self.app_log_group,
            metric_namespace="LogSentinel",
            metric_name="CriticalWebEvents",
            filter_pattern=logs.FilterPattern.literal(
                '{ ($.event_type = "MFA_BYPASS_ATTEMPT") || ($.event_type = "SQL_INJECTION") }'
            ),
            metric_value="1",
        )
        self.critical_web_alarm = cloudwatch.Alarm(
            self, "CriticalWebEventsAlarm",
            alarm_description="Co su kien web nghiem trong (MFA bypass / SQL injection).",
            metric=self.critical_web_filter.metric(statistic="Sum", period=five_min),
            threshold=1, evaluation_periods=1,
            comparison_operator=breach, treat_missing_data=no_data,
        )

        # 3. CloudTrail bi tat/xoa: canh bao doc lap voi Lambda (phong thu nhieu lop).
        self.trail_tamper_filter = logs.MetricFilter(
            self, "TrailTamperFilter",
            log_group=self.trail_log_group,
            metric_namespace="LogSentinel",
            metric_name="CloudTrailTampering",
            filter_pattern=logs.FilterPattern.literal(
                '{ ($.eventName = "StopLogging") || ($.eventName = "DeleteTrail") }'
            ),
            metric_value="1",
        )
        self.trail_tamper_alarm = cloudwatch.Alarm(
            self, "CloudTrailTamperAlarm",
            alarm_description="CloudTrail bi tat hoac xoa (StopLogging / DeleteTrail).",
            metric=self.trail_tamper_filter.metric(statistic="Sum", period=five_min),
            threshold=1, evaluation_periods=1,
            comparison_operator=breach, treat_missing_data=no_data,
        )

        alarms = [self.detector_error_alarm, self.critical_web_alarm, self.trail_tamper_alarm]
        if self.edge:
            # 4. Dong bo WAF hong: IP bi khoa khong con duoc chan o bien (web app van tu chan).
            # 3 lan lien tiep moi bao, de 1 lan loi mang le te khong lam phien.
            self.waf_sync_error_alarm = cloudwatch.Alarm(
                self, "WafSyncErrorsAlarm",
                alarm_description="Lambda dong bo IP bi khoa len WAF bao loi lien tuc.",
                metric=self.waf_sync_lambda.metric_errors(period=five_min),
                threshold=3, evaluation_periods=1,
                comparison_operator=breach, treat_missing_data=no_data,
            )
            alarms.append(self.waf_sync_error_alarm)
        for alarm in alarms:
            alarm.add_alarm_action(action)

    def _build_monitoring_dashboard(self) -> None:
        incidents = lambda sev: cloudwatch.Metric(  # noqa: E731
            namespace="LogSentinel", metric_name="IncidentsDetected",
            dimensions_map={"Severity": sev}, statistic="Sum",
            period=Duration.minutes(5), label=sev,
        )
        self.dashboard = cloudwatch.Dashboard(self, "LogSentinelDashboard", dashboard_name="LogSentinel-Overview")
        self.dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Su co phat hien theo muc do (EMF tu Detector)",
                left=[incidents("CRITICAL"), incidents("HIGH")],
                width=12
            ),
            cloudwatch.AlarmStatusWidget(
                title="Trang thai Alarm",
                alarms=[self.detector_error_alarm, self.critical_web_alarm, self.trail_tamper_alarm],
                width=12
            ),
        )
        self.dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Lambda Invocations & Errors",
                left=[self.detector_lambda.metric_invocations()],
                right=[self.detector_lambda.metric_errors()],
                width=12
            ),
            cloudwatch.LogQueryWidget(
                title="20 su co gan nhat",
                log_group_names=[self.detector_log_group.log_group_name],
                query_lines=[
                    "fields @timestamp, Severity, Rule",
                    "filter ispresent(IncidentsDetected)",
                    "sort @timestamp desc",
                    "limit 20",
                ],
                width=12
            ),
        )

    def _export_outputs(self) -> None:
        CfnOutput(self, "IncidentTableName", value=self.incident_table.table_name)
        CfnOutput(self, "AppLogGroupName", value=self.app_log_group.log_group_name)
        CfnOutput(self, "TelegramSecretArn", value=self.telegram_secret.secret_arn)
        CfnOutput(self, "UserPoolId", value=self.user_pool.user_pool_id,
                  description="Cognito: nang quyen quan tri vien dau tien bang `aws cognito-idp admin-add-user-to-group`")
        CfnOutput(self, "UserPoolClientId", value=self.user_pool_client.user_pool_client_id)
