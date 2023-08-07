import re
import fitz  # PyMuPDF
import json
import sys

def extract_text_from_pdf(pdf_file):
    text = ""
    with fitz.open(pdf_file) as pdf_document:
        for page_number in range(pdf_document.page_count):
            page = pdf_document.load_page(page_number)
            text += page.get_text()

    return text

def extract_mitre_attack_ids(input_string):
    mitre_attack_id_pattern = r'T\d{4}\.\d{3}'
    technique_ids = re.findall(mitre_attack_id_pattern, input_string)
    return technique_ids

def extract_mitre_attack_ids_without_decimal(input_string):
    # Regular expression pattern to match MITRE ATT&CK technique IDs without decimal part
    mitre_attack_id_pattern = r'T\d{4}(?!\.)'
    technique_ids = re.findall(mitre_attack_id_pattern, input_string)
    return technique_ids


banner = '''
  _____                       _   ___        _______ _______       _____ _  __
 |  __ \                     | | |__ \    /\|__   __|__   __|/\   / ____| |/ /
 | |__) |___ _ __   ___  _ __| |_   ) |  /  \  | |     | |  /  \ | |    | ' / 
 |  _  // _ \ '_ \ / _ \| '__| __| / /  / /\ \ | |     | | / /\ \| |    |  <  
 | | \ \  __/ |_) | (_) | |  | |_ / /_ / ____ \| |     | |/ ____ \ |____| . \ 
 |_|  \_\___| .__/ \___/|_|   \__|____/_/    \_\_|     |_/_/    \_\_____|_|\_|
            | |                                                               
            |_|                                                               
'''

if __name__ == "__main__":

    print(banner)
    pdf_file_path = input("Enter the report path: ")

    try:
        extracted_text = extract_text_from_pdf(pdf_file_path)
        extracted_ids_with_decimal = extract_mitre_attack_ids(extracted_text)
        extracted_ids_without_decimal = extract_mitre_attack_ids_without_decimal(extracted_text)

        # Store extracted technique IDs in lists
        all_technique_ids = extracted_ids_with_decimal + extracted_ids_without_decimal

        if all_technique_ids:
            print("All MITRE ATT&CK technique IDs were extracted successfully:")
            nav_layer_name = input("Enter the ATT&CK Navigation Layer Name (Optional): ")
            nav_layer_description = input("Enter the ATT&CK Navigation Layer Description (Optional): ")
            nav_layer_output = input("Enter the ATT&CK Navigation Layer Output File Name: ")
            # Generate MITRE Layer
            Layer_Template = {
                "description": str(nav_layer_description),
                "name": str(nav_layer_name),
                "domain": "mitre-enterprise",
                "version": "4.4",
                "techniques": 
                    [{  "techniqueID": technique, "color": "#e6550d","score": 1  } for technique in all_technique_ids] 
                ,
                "gradient": {
                    "colors": [
                        "#ffffff",
                        "#e6550d"
                    ],
                    "minValue": 0,
                    "maxValue": 1
                },
                "legendItems": [
                    {
                        "label": "Techniques Covered by DarkTrace",
                        "color": "#e6550d"
                    }
                ]
                            }

            json_data = json.dumps(Layer_Template)

            with open(str(nav_layer_output+".json"), "w") as file:
                json.dump(Layer_Template, file)
        else:
            print("No MITRE ATT&CK technique IDs found in the PDF.")
    except Exception as e:
        print("Error occurred while processing the PDF:", e)
