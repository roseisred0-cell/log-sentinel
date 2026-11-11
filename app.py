#!/usr/bin/env python3
"""
Hai che do trien khai:

  Truc tiep (mac dinh, lab):
      cdk deploy -c alert_email=<email> -c admin_cidr=<ip>/32

  Edge (san xuat): CloudFront + WAF truoc may. WAF cho CloudFront bat buoc o us-east-1 -> them 1 stack.
      cdk bootstrap aws://<account>/us-east-1          # chi can 1 lan
      cdk deploy --all -c enable_edge=true -c alert_email=<email> -c admin_cidr=<ip>/32
"""
import os

import aws_cdk as cdk

from log_sentinel.edge_stack import LogSentinelEdgeStack
from log_sentinel.log_sentinel_stack import LogSentinelStack, console_cidrs, edge_enabled


app = cdk.App()
account = os.getenv("CDK_DEFAULT_ACCOUNT")
use_edge = edge_enabled(app)

edge = None
if use_edge:
    edge = LogSentinelEdgeStack(
        app,
        "LogSentinelEdgeStack",
        console_cidrs=console_cidrs(app),
        env=cdk.Environment(account=account, region="us-east-1"),
        cross_region_references=True,
        description="LogSentinel edge: AWS WAF cho CloudFront (bat buoc o us-east-1)",
    )

LogSentinelStack(
    app,
    "LogSentinelStack",
    edge=edge,
    env=cdk.Environment(
        account=account,
        region=os.getenv("CDK_DEFAULT_REGION", "ap-southeast-1")
    ),
    cross_region_references=use_edge,
    description="LogSentinel Infrastructure for FCAJ Project"
)

app.synth()
