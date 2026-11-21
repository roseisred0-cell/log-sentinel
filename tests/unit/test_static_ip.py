"""IP tinh (Elastic IP), nhat ky 12/11 muc 4.E1. May duoc Stop/Start hang ngay: IP cong khai thuong doi moi lan Start.

    cdk deploy -c static_ip=true          (che do truc tiep)
    cdk deploy --all -c enable_edge=true  (che do edge: IP tinh tu bat, vi CloudFront tro toi ten DNS cua may)
"""
import json

import aws_cdk as core
import aws_cdk.assertions as assertions
import pytest

from log_sentinel.edge_stack import LogSentinelEdgeStack
from log_sentinel.log_sentinel_stack import LogSentinelStack

ACCOUNT = "123456789012"
ENV = core.Environment(account=ACCOUNT, region="ap-southeast-1")


def _direct(**context):
    return assertions.Template.from_stack(LogSentinelStack(core.App(context=context), "ip-test", env=ENV))


@pytest.fixture(scope="module")
def edge_main():
    app = core.App(context={"enable_edge": "true"})
    edge = LogSentinelEdgeStack(app, "edge-ip", env=core.Environment(account=ACCOUNT, region="us-east-1"),
                                cross_region_references=True)
    main = LogSentinelStack(app, "main-ip", edge=edge, env=ENV, cross_region_references=True)
    return assertions.Template.from_stack(main)


def _only(template, resource_type):
    found = template.find_resources(resource_type)
    assert len(found) == 1, found
    return next(iter(found.items()))


def test_no_elastic_ip_by_default():
    """Elastic IP tinh phi ca luc may tat (khoang 3,6 USD/thang): chi tao khi duoc yeu cau."""
    t = _direct()
    assert t.find_resources("AWS::EC2::EIP") == {} and t.find_resources("AWS::EC2::EIPAssociation") == {}


def test_static_ip_is_attached_through_an_association_that_follows_instance_replacement():
    """Lien ket tro toi Ref cua may: cdk deploy thay may moi -> CloudFormation chuyen IP sang may moi."""
    t = _direct(static_ip="true")
    eip_id, eip = _only(t, "AWS::EC2::EIP")
    assert eip["Properties"]["Domain"] == "vpc"
    _, assoc = _only(t, "AWS::EC2::EIPAssociation")
    props = assoc["Properties"]
    assert props["AllocationId"] == {"Fn::GetAtt": [eip_id, "AllocationId"]}
    vm_id = next(iter(t.find_resources("AWS::EC2::Instance")))
    assert props["InstanceId"] == {"Ref": vm_id}


def test_console_url_uses_the_static_ip():
    t = _direct(static_ip="true")
    eip_id, _ = _only(t, "AWS::EC2::EIP")
    url = json.dumps(t.find_outputs("SocConsoleUrl"))
    assert eip_id in url and "PublicIp" in url
    assert "TargetWebServerVM" not in url  # khong con dung IP tu cap (doi moi lan Start)
    t.has_output("StaticPublicIp", {})


def test_edge_mode_turns_the_static_ip_on_and_points_cloudfront_at_it(edge_main):
    eip_id, _ = _only(edge_main, "AWS::EC2::EIP")
    _, dist = _only(edge_main, "AWS::CloudFront::Distribution")
    origin = json.dumps(dist["Properties"]["DistributionConfig"]["Origins"][0]["DomainName"])
    assert eip_id in origin and "compute.amazonaws.com" in origin
    assert "PublicDnsName" not in origin  # ten DNS tu cap cua may doi moi lan Start -> CloudFront loi 502


@pytest.mark.parametrize("value", ["false", "0", "no", ""])
def test_static_ip_flag_accepts_only_explicit_true(value):
    assert _direct(static_ip=value).find_resources("AWS::EC2::EIP") == {}
