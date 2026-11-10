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
)
from constructs import Construct


ROOT_DIR = Path(__file__).resolve().parent.parent
WEBAPP_DIR = ROOT_DIR / "sample_app"


class LogSentinelConfig:
    """Hang so khong nhay cam. Gia tri rieng tu (email, IP) lay tu context/env, KHONG commit vao Git:

        cdk deploy -c alert_email=soc@example.com -c admin_cidr=203.0.113.10/32
    """
    PROJECT_NAME = "LogSentinel"
    LOG_RETENTION_DAYS = logs.RetentionDays.ONE_WEEK
    S3_EXPIRATION_DAYS = 30

    def __init__(self, scope: Construct):
        def ctx(key: str, env_key: str, default: str = "") -> str:
            return str(scope.node.try_get_context(key) or os.environ.get(env_key) or default).strip()

        self.alert_email = ctx("alert_email", "LOGSENTINEL_ALERT_EMAIL")
        # IP quan tri: khong bao gio bi SOAR khoa (chong tu khoa chinh minh khi demo).
        self.admin_cidr = ctx("admin_cidr", "LOGSENTINEL_ADMIN_CIDR")
        # Ai duoc goi HTTPS 443 toi may muc tieu (mac dinh Internet de demo tan cong).
        self.ingress_cidr = ctx("ingress_cidr", "LOGSENTINEL_INGRESS_CIDR", "0.0.0.0/0")


class LogSentinelStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.cfg = LogSentinelConfig(self)

        self._build_security_and_storage()
        self._build_log_ingestion()
        self._build_detection_and_alerting()
        self._build_target_ec2_vm()
        self._build_alarms()
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

    def _build_detection_and_alerting(self) -> None:
        self.alert_topic = sns.Topic(self, "SecurityAlertTopic", display_name="LogSentinel Alerts")
        if self.cfg.alert_email:
            self.alert_topic.add_subscription(subs.EmailSubscription(self.cfg.alert_email))
        else:
            Annotations.of(self).add_warning(
                "Chua co alert_email: SNS se khong gui email. Dung: cdk deploy -c alert_email=<email>")

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
            filter_pattern=logs.FilterPattern.any_term(
                "ConsoleLogin",
                "DeactivateMFADevice",
                "DeleteVirtualMFADevice",
                "StopLogging",
                "DeleteTrail",
                "CreateAccessKey",
                "AttachUserPolicy",
                "PutUserPolicy"
            )
        )

    def _build_target_ec2_vm(self) -> None:
        """Nginx TLS 443 -> Gunicorn 127.0.0.1:8080. Code + cau hinh ship bang S3 asset (khong nhoi vao UserData)."""
        vpc = ec2.Vpc.from_lookup(self, "DefaultVPC", is_default=True)

        self.vm_sg = ec2.SecurityGroup(
            self, "TargetVmSecurityGroup",
            vpc=vpc,
            description="LogSentinel target: chi HTTPS 443 qua Nginx. 8080 chi bind loopback.",
            allow_all_outbound=True
        )
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
        # Web app chi can doc 1 khoa BLOCKED_IP#<ip> -> GetItem, khong Scan/Query ca bang.
        vm_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:GetItem"],
            resources=[self.incident_table.table_arn],
        ))
        self.kms_key.grant_decrypt(vm_role)

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
        user_data.add_commands(
            "mkdir -p /opt/logsentinel/app",
            f"unzip -o {zip_path} -d /opt/logsentinel/app",
            f"INCIDENT_TABLE={self.incident_table.table_name} AWS_REGION={self.region} "
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

        CfnOutput(self, "TargetVmAttackUrl", value=f"https://{self.target_vm.instance_public_ip}")
        CfnOutput(self, "TargetVmInstanceId", value=self.target_vm.instance_id,
                  description="Lay mat khau/TOTP: aws ssm start-session --target <id>, roi sudo cat /etc/logsentinel/webapp.env")

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

        for alarm in (self.detector_error_alarm, self.critical_web_alarm, self.trail_tamper_alarm):
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
