def calculate_compliance_score(check_results):
    """
    audit_results is a list of dictionaries returned from your checks:
    [
      {"Status": "FAIL", "Severity": "High", "Message": "..."},
      {"Status": "PASS", "Severity": "Medium", "Message": "..."},
    ]
    """

    # 1. Define weights for the severities
    severity_weights = {
        "Critical": 10,
        "High": 5,
        "Medium": 3,
        "Low": 1
    }
    total_possible_score = 0
    actual_score = 0
    
    summary = {
        "Total_Checks": len(check_results),
        "Passed": 0,
        "Failed": 0,
        "Failures_By_Severity": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    }
    # 2. Iterate through results and do the math
    for index, result in check_results.items():
        status = result.get("Status")
        severity = result.get("Severity", "Low")
        weight = severity_weights.get(severity, 1)

        # Every check adds to the total possible score
        total_possible_score += weight

        if status == "PASS":
            summary["Passed"] += 1
            actual_score += weight  # Give them the points
            
        elif status == "FAIL":
            summary["Failed"] += 1
            summary["Failures_By_Severity"][severity] += 1
            # 0 points awarded for a fail

    # 3. Calculate final percentage
    if total_possible_score == 0:
        compliance_percentage = 100.0  # Prevent division by zero if no checks ran
    else:
        compliance_percentage = (actual_score / total_possible_score) * 100

    summary["Compliance_Score_Percentage"] = round(compliance_percentage, 2)

    # Optional: Assign a letter grade
    if compliance_percentage >= 90:
        summary["Grade"] = "A"
    elif compliance_percentage >= 80:
        summary["Grade"] = "B"
    elif compliance_percentage >= 70:
        summary["Grade"] = "C"
    else:
        summary["Grade"] = "F"

    return summary