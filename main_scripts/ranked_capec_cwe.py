import csv
import xml.etree.ElementTree as ET

def parse_capec_data(capec_file):
    capec_data = {}
    with open(capec_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            capec_id = int(row["'ID"])  # Correcting ID extraction
            likelihood = row['Likelihood Of Attack']
            severity = row['Typical Severity']
            capec_data[capec_id] = {
                'likelihood': likelihood,
                'severity': severity
            }
    return capec_data

def parse_cwe_data(cwe_file):
    tree = ET.parse(cwe_file)
    root = tree.getroot()

    # Handle the namespace for the CWE XML
    namespace = {'ns': 'http://cwe.mitre.org/cwe-7'}

    cwe_data = {}
    for weakness in root.findall(".//ns:Weakness", namespaces=namespace):
        cwe_id = int(weakness.attrib['ID'])
        likelihood_elem = weakness.find("ns:Likelihood_Of_Exploit", namespaces=namespace)
        consequences = [
            {
                'scope': consequence.find("ns:Scope", namespaces=namespace).text,
                'impact': consequence.find("ns:Impact", namespaces=namespace).text
            }
            for consequence in weakness.findall("ns:Common_Consequences/ns:Consequence", namespaces=namespace)
        ]

        # Handle related weaknesses
        related_weaknesses = [
            int(rel.attrib['CWE_ID']) for rel in
            weakness.findall("ns:Related_Weaknesses/ns:Related_Weakness", namespaces=namespace)
        ]

        cwe_data[cwe_id] = {
            'likelihood': likelihood_elem.text if likelihood_elem is not None else "Unknown",
            'consequences': consequences,
            'related_weaknesses': related_weaknesses
        }
    return cwe_data

def compute_risk(capec_cwe_pairs, capec_data, cwe_data):
    risk_ratings = []
    for capec_id, cwe_id in capec_cwe_pairs:
        capec_info = capec_data.get(capec_id, {})
        cwe_info = cwe_data.get(cwe_id, {})

        # Assign numerical scores to likelihood and severity
        likelihood_map = {'Low': 1, 'Medium': 2, 'High': 3, 'Unknown': 0}
        severity_map = {'Low': 1, 'Medium': 2, 'High': 3, 'Unknown': 0}

        capec_likelihood = likelihood_map.get(capec_info.get('likelihood', 'Unknown'), 0)
        capec_severity = severity_map.get(capec_info.get('severity', 'Unknown'), 0)

        cwe_likelihood = likelihood_map.get(cwe_info.get('likelihood', 'Unknown'), 0)
        cwe_impact_score = sum(
            severity_map.get(consequence['impact'], 0) for consequence in cwe_info.get('consequences', [])
        )

        # Compute combined risk score
        risk_score = (capec_likelihood * 2 + capec_severity * 2 + cwe_likelihood + cwe_impact_score)
        risk_ratings.append((capec_id, cwe_id, risk_score))

    # Sort pairs by risk score in descending order
    risk_ratings.sort(key=lambda x: x[2], reverse=True)
    return risk_ratings

def categorize_and_display_results(risk_ratings):
    high_risk = []
    medium_risk = []
    low_risk = []

    # Define risk score thresholds
    for capec_id, cwe_id, risk_score in risk_ratings:
        if risk_score >= 15:  # Example threshold for High risk
            high_risk.append((capec_id, cwe_id, risk_score))
        elif 10 <= risk_score < 15:  # Example threshold for Medium risk
            medium_risk.append((capec_id, cwe_id, risk_score))
        else:  # Low risk
            low_risk.append((capec_id, cwe_id, risk_score))

    # Display results
    if high_risk:
        print("High Risk:")
        for capec_id, cwe_id, risk_score in high_risk:
            print(f"  CAPEC-{capec_id} + CWE-{cwe_id} => Risk Score: {risk_score}")

    if medium_risk:
        print("\nMedium Risk:")
        for capec_id, cwe_id, risk_score in medium_risk:
            print(f"  CAPEC-{capec_id} + CWE-{cwe_id} => Risk Score: {risk_score}")

    if low_risk:
        print("\nLow Risk:")
        for capec_id, cwe_id, risk_score in low_risk:
            print(f"  CAPEC-{capec_id} + CWE-{cwe_id} => Risk Score: {risk_score}")

# Example usage
capec_file = r'C:\PycharmProjects\diplom\main_scripts\capec_data\1000.csv'  # Use raw string
cwe_file = r'C:\PycharmProjects\diplom\main_scripts\cwe_data\cwec_v4.16.xml'  # Adjust to actual XML path

# Load data
capec_data = parse_capec_data(capec_file)
cwe_data = parse_cwe_data(cwe_file)

# Example input: list of CAPEC + CWE pairs
capec_cwe_pairs = [
    (1, 1004),  # High Risk
    (2, 1190),  # High Risk
    (3, 20),    # Medium Risk
    (4, 79),    # Medium Risk
    (5, 89),    # Medium Risk
    (6, 77),    # Low Risk
    (7, 22),    # Low Risk
    (8, 200),   # High Risk
    (9, 732),   # Medium Risk
    (10, 476),  # High Risk
    (11, 119),  # Low Risk
    (12, 190),  # Medium Risk
    (13, 200),  # Medium Risk
    (14, 399),  # High Risk
    (15, 200),  # Low Risk
]

# Compute risk ratings
risk_ratings = compute_risk(capec_cwe_pairs, capec_data, cwe_data)

# Categorize and display results
categorize_and_display_results(risk_ratings)
