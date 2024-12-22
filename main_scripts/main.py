# 1.0
import json
from main_scripts import generate_workers_ib, generate_szi, get_mitigations_and_detections_by_teckniques, find_cves_by_teckniques, calculate_risk, Generate_pdf, generate_protection_objects, generate_offenders

list_tecknique = ['1560','1584.005','1189','1553','1021.001','1583.002','1566','1190','1003']
tables = []
tables.append(Generate_pdf.create_table_1(list_tecknique))

dict_cves_by_teckniques = find_cves_by_teckniques.find_cves_by_techniques(list_tecknique)
with open("C:\\PycharmProjects\\diplom\\CVE2CAPEC\\resultscve\\minimal_all_data.json", "r", encoding="utf-8") as file:
    data = json.load(file)
for tecknique in dict_cves_by_teckniques.keys():
    if len(dict_cves_by_teckniques[tecknique]) > 10:
        risk = calculate_risk.analyze_cve_data(data, tecknique, dict_cves_by_teckniques[tecknique])
        # Шаг 1: Сортировка по риску в порядке убывания
        sorted_risk = sorted(risk, key=lambda x: x['Risk'], reverse=True)
        # Шаг 2: Извлечение CVE_ID (максимум 10)
        top_cve_ids = [entry['CVE_ID'] for entry in sorted_risk[:10]]
        dict_cves_by_teckniques[tecknique] = top_cve_ids
del data
tables.append(Generate_pdf.create_table_2(dict_cves_by_teckniques))

teh_cve_pair = []
for tecknique in dict_cves_by_teckniques.keys():
    if len(dict_cves_by_teckniques[tecknique]) != 0:
        for cve in dict_cves_by_teckniques[tecknique]:
            teh_cve_pair.append((tecknique, cve))
    else:
        teh_cve_pair.append((tecknique, '-'))

protection_objects = generate_protection_objects.main(teh_cve_pair)
tables.append(Generate_pdf.create_table_3(protection_objects))

offenders = generate_offenders.main([item[:-1] for item in protection_objects])
tables.append(Generate_pdf.create_table_4(offenders))

mitigations, detections = get_mitigations_and_detections_by_teckniques.main(list_tecknique)
tables.append(Generate_pdf.create_table_5(detections))
tables.append(Generate_pdf.create_table_6(mitigations))

workers = generate_workers_ib.match_competencies_with_techniques(list_tecknique)
tables.append(Generate_pdf.create_table_7(workers))

szi = generate_szi.match_techniques_with_szi(list_tecknique)
tables.append(Generate_pdf.create_table_8(szi))

Generate_pdf.create_pdf(tables, "C:\PycharmProjects\diplom\main_scripts\mitre_techniques.pdf")
print("Финальная таблица с документацией успешно создана!")