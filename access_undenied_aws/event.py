from __future__ import annotations

from typing import Dict


class Event(object):
    def __init__(self, raw_event: Dict):
        self.error_code = raw_event.get("errorCode")
        self.error_message = raw_event.get("errorMessage")
        self.event_id = raw_event.get("eventID")
        self.event_name = raw_event.get("eventName")
        self.event_source = raw_event.get("eventSource")
        self.event_time = raw_event.get("eventTime")
        self.principal_type = raw_event.get("userIdentity", {}).get("type")
        self.raw_principal = raw_event.get("userIdentity")
        self.raw_resources = raw_event.get("resources")
        self.raw_request_parameters = raw_event.get("requestParameters")
        self.region = raw_event.get("awsRegion")
        self.source_ip_address = raw_event.get("sourceIPAddress")
        self.vpc_endpoint_id = raw_event.get("vpcEndpointId")
