#!/usr/bin/env python3
import os

import aws_cdk as cdk

from log_sentinel.log_sentinel_stack import LogSentinelStack


app = cdk.App()
LogSentinelStack(
    app, 
    "LogSentinelStack",
    env=cdk.Environment(
        account=os.getenv("CDK_DEFAULT_ACCOUNT"),
        region=os.getenv("CDK_DEFAULT_REGION", "ap-southeast-1")
    ),
    description="LogSentinel Infrastructure for FCAJ Project"
)

app.synth()
