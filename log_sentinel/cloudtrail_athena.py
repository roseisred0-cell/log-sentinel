"""
Dinh nghia bang Athena cho log CloudTrail tren S3 (Glue Data Catalog).

Cot, SerDe va dinh dang lay nguyen tu tai lieu AWS:
  "Create the table for CloudTrail logs in Athena using partition projection"
  https://docs.aws.amazon.com/athena/latest/ug/create-cloudtrail-table-partition-projection.html

Khac voi vi du trong tai lieu (1 region): trail cua LogSentinel la multi-region, nen them khoa phan vung `region`
(kieu enum). Partition projection = Athena tu suy ra phan vung tu duong dan, khong can chay ALTER TABLE hay crawler.
"""

TABLE_NAME = "cloudtrail_logs"

_USER_IDENTITY = (
    "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,"
    "username:string,onbehalfof:struct<userid:string,identitystorearn:string>,"
    "sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,"
    "sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>,"
    "ec2roledelivery:string,"
    "webidfederationdata:struct<federatedprovider:string,attributes:map<string,string>>>>"
)

COLUMNS = (
    ("eventversion", "string"),
    ("useridentity", _USER_IDENTITY),
    ("eventtime", "string"),
    ("eventsource", "string"),
    ("eventname", "string"),
    ("awsregion", "string"),
    ("sourceipaddress", "string"),
    ("useragent", "string"),
    ("errorcode", "string"),
    ("errormessage", "string"),
    ("requestparameters", "string"),
    ("responseelements", "string"),
    ("additionaleventdata", "string"),
    ("requestid", "string"),
    ("eventid", "string"),
    ("readonly", "string"),
    ("resources", "array<struct<arn:string,accountid:string,type:string>>"),
    ("eventtype", "string"),
    ("apiversion", "string"),
    ("recipientaccountid", "string"),
    ("serviceeventdetails", "string"),
    ("sharedeventid", "string"),
    ("vpcendpointid", "string"),
    ("vpcendpointaccountid", "string"),
    ("eventcategory", "string"),
    ("addendum", "struct<reason:string,updatedfields:string,originalrequestid:string,originaleventid:string>"),
    ("sessioncredentialfromconsole", "string"),
    ("edgedevicedetails", "string"),
    ("tlsdetails", "struct<tlsversion:string,ciphersuite:string,clientprovidedhostheader:string>"),
)

# Region bat mac dinh cho moi tai khoan. Su kien IAM / dang nhap Console la su kien toan cau, nam o us-east-1.
REGIONS = (
    "us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1", "sa-east-1",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-south-1",
)

PARTITION_KEYS = (("region", "string"), ("day", "string"))


def table_input(bucket_name: str, account: str, first_day: str = "2026/01/01") -> dict:
    """TableInput cho AWS::Glue::Table. `first_day` (yyyy/MM/dd): ngay som nhat Athena tim du lieu."""
    root = f"s3://{bucket_name}/AWSLogs/{account}/CloudTrail/"
    return {
        "name": TABLE_NAME,
        "description": "Log CloudTrail cua tai khoan (multi-region), phan vung theo region va ngay",
        "tableType": "EXTERNAL_TABLE",
        "partitionKeys": [{"name": n, "type": t} for n, t in PARTITION_KEYS],
        "parameters": {
            "classification": "cloudtrail",
            "projection.enabled": "true",
            "projection.region.type": "enum",
            "projection.region.values": ",".join(REGIONS),
            "projection.day.type": "date",
            "projection.day.format": "yyyy/MM/dd",
            "projection.day.interval": "1",
            "projection.day.interval.unit": "DAYS",
            "projection.day.range": f"{first_day},NOW",
            "storage.location.template": root + "${region}/${day}",
        },
        "storageDescriptor": {
            "location": root,
            "columns": [{"name": n, "type": t} for n, t in COLUMNS],
            "inputFormat": "com.amazon.emr.cloudtrail.CloudTrailInputFormat",
            "outputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
            "serdeInfo": {"serializationLibrary": "org.apache.hive.hcatalog.data.JsonSerDe"},
        },
    }


# ------------------------------------------------------------------ truy van mau
# Moi cau deu loc theo `day` (khoa phan vung): Athena chi doc cac thu muc ngay can thiet -> nhanh va re.
_LAST_7_DAYS = "day >= date_format(current_date - interval '7' day, '%Y/%m/%d')"
_LAST_30_DAYS = "day >= date_format(current_date - interval '30' day, '%Y/%m/%d')"

NAMED_QUERIES = (
    ("LogSentinel - Events per day (30 days)",
     "Number of CloudTrail events per day: trend chart for the report",
     f"SELECT day, count(*) AS events, count(DISTINCT sourceipaddress) AS distinct_ips "
     f"FROM cloudtrail_logs WHERE {_LAST_30_DAYS} GROUP BY day ORDER BY day"),
    ("LogSentinel - Top actions (7 days)",
     "Most frequently called services and actions",
     f"SELECT eventsource, eventname, count(*) AS calls "
     f"FROM cloudtrail_logs WHERE {_LAST_7_DAYS} GROUP BY eventsource, eventname ORDER BY calls DESC LIMIT 50"),
    ("LogSentinel - Failed Console sign-ins by IP (7 days)",
     "Signs of AWS Console password guessing",
     f"SELECT sourceipaddress, useridentity.username AS username, count(*) AS failures, max(eventtime) AS last_seen "
     f"FROM cloudtrail_logs WHERE {_LAST_7_DAYS} AND eventname = 'ConsoleLogin' "
     f"AND json_extract_scalar(responseelements, '$.ConsoleLogin') = 'Failure' "
     f"GROUP BY sourceipaddress, useridentity.username ORDER BY failures DESC"),
    ("LogSentinel - Recent IAM changes",
     "Every IAM write action in the last 7 days: who, from where, and whether it was denied",
     f"SELECT eventtime, eventname, useridentity.arn AS actor, sourceipaddress, errorcode "
     f"FROM cloudtrail_logs WHERE {_LAST_7_DAYS} AND eventsource = 'iam.amazonaws.com' AND readonly = 'false' "
     f"ORDER BY eventtime DESC LIMIT 200"),
    ("LogSentinel - Denied API calls (7 days)",
     "Who is trying to do things they are not allowed to",
     f"SELECT useridentity.arn AS actor, eventsource, eventname, errorcode, count(*) AS calls "
     f"FROM cloudtrail_logs WHERE {_LAST_7_DAYS} "
     f"AND errorcode IN ('AccessDenied', 'UnauthorizedOperation', 'Client.UnauthorizedOperation') "
     f"GROUP BY useridentity.arn, eventsource, eventname, errorcode ORDER BY calls DESC LIMIT 100"),
)
