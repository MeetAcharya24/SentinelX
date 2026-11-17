import json

from fastapi.testclient import TestClient

URL = "/api/v1/logs/validate"
CSV = {"content-type": "text/csv"}
CSV_LOG = b"""timestamp,event_type,source_ip,user,status,asset_id,session
2026-11-16T08:05:00Z,login_failure,203.0.113.45,admin,fail,vpn-01,s1
2026-11-16T08:00:00Z,login_success,192.0.2.10,alice,success,web-01,s2
2026-11-16T09:30:00+01:00,login_failure,203.0.113.45,admin,fail,vpn-01,s3
2026-11-16T08:10:00Z,access,192.0.2.10,,success,,s4
"""


def test_valid_csv_log_is_summarised(client: TestClient) -> None:
    response = client.post(URL, content=CSV_LOG, headers=CSV)

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["data"] == {
        "format": "csv",
        "event_count": 4,
        "first_timestamp": "2026-11-16T08:00:00Z",
        "last_timestamp": "2026-11-16T08:30:00Z",
        "event_types": [
            {"event_type": "login_failure", "count": 2},
            {"event_type": "access", "count": 1},
            {"event_type": "login_success", "count": 1},
        ],
        "distinct_event_types": 3,
        "status_counts": {"success": 2, "fail": 2},
        "distinct_source_ips": 2,
        "distinct_users": 2,
        "ignored_fields": ["session"],
    }


def test_valid_json_log_is_summarised(client: TestClient) -> None:
    events = [
        {
            "timestamp": "2026-11-16T08:00:00Z",
            "event_type": "config_change",
            "source_ip": "2001:db8::1",
            "status": "success",
        }
    ]

    response = client.post(URL, json=events)

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["format"] == "json"
    assert data["event_count"] == 1
    assert data["status_counts"] == {"success": 1, "fail": 0}
    assert data["distinct_users"] == 0


def test_content_type_parameters_and_case_are_accepted(client: TestClient) -> None:
    response = client.post(
        URL, content=CSV_LOG, headers={"content-type": "Text/CSV; charset=utf-8"}
    )

    assert response.status_code == 200


def test_event_type_list_is_capped_but_all_types_are_counted(client: TestClient) -> None:
    events = [
        {
            "timestamp": "2026-11-16T08:00:00Z",
            "event_type": f"type_{index}",
            "source_ip": "192.0.2.10",
            "status": "success",
        }
        for index in range(30)
    ]

    data = client.post(URL, json=events).json()["data"]

    assert len(data["event_types"]) == 20
    assert data["distinct_event_types"] == 30


def test_unsupported_content_type_is_refused(client: TestClient) -> None:
    for headers in ({"content-type": "application/pdf"}, {}):
        response = client.post(URL, content=CSV_LOG, headers=headers)

        assert response.status_code == 415
        assert response.json()["error"]["code"] == "unsupported_log_type"


def test_invalid_rows_reject_the_file_with_details(client: TestClient) -> None:
    log = CSV_LOG + b"not-a-time,access,<b>nowhere</b>,,success,,s5\n"

    response = client.post(URL, content=log, headers=CSV)

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "invalid_log_file"
    assert "2 problems" in error["message"]
    assert [(d["row"], d["field"]) for d in error["details"]] == [
        (5, "timestamp"),
        (5, "source_ip"),
    ]
    assert "<b>" not in json.dumps(error)


def test_file_level_problem_has_no_row_details(client: TestClient) -> None:
    response = client.post(URL, content=b"", headers=CSV)

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "invalid_log_file"
    assert error["details"] is None


def test_json_body_is_not_treated_as_a_typed_request_model(client: TestClient) -> None:
    response = client.post(URL, content=b"{not json", headers={"content-type": "application/json"})

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_log_file"


def test_oversized_log_is_refused_before_parsing(client: TestClient) -> None:
    response = client.post(URL, content=b"x" * 1_048_577, headers=CSV)

    assert response.status_code == 413
