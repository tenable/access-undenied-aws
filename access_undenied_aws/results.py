from __future__ import annotations

import json

from access_undenied_aws import common
from access_undenied_aws import result_details


class Result(object):
    def __init__(
        self, event_id: str, assessment_result: common.AccessDeniedReason
    ) -> None:
        self.event_id = event_id
        self.assessment_result = assessment_result

    def __str__(self) -> str:
        output = dict()
        output["EventId"] = self.event_id
        if self.assessment_result:
            output["AssessmentResult"] = self.assessment_result
        return json.dumps(output, indent=2)


class ErrorResult(Result):
    def __init__(
        self,
        event_id: str,
        assessment_result: common.AccessDeniedReason,
        error_message: str,
    ):
        super(ErrorResult, self).__init__(event_id, assessment_result)
        self.error_message = error_message

    def __str__(self) -> str:
        output = json.loads(super(ErrorResult, self).__str__())
        output["ErrorMessage"] = self.error_message
        return json.dumps(output, indent=2)


class AnalysisResult(Result):
    def __init__(
        self,
        event_id: str,
        assessment_result: common.AccessDeniedReason,
        result_details_: result_details.ResultDetails,
    ):
        super().__init__(event_id, assessment_result)
        self.result_details = result_details_

    def __str__(self) -> str:
        output = json.loads(super(AnalysisResult, self).__str__())
        if self.result_details:
            output["ResultDetails"] = json.loads(str(self.result_details))
        return json.dumps(output, indent=2)
