import streamlit as st
import requests
import xmltodict
from jinja2 import Environment, FileSystemLoader
import os
import shutil

# Suppress SSL warnings for demo purposes
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

st.title("Palo Alto to Fortinet Terraform Converter")

# Add option to select configuration source
option = st.radio("Select Configuration Source", ('Upload Config File', 'Log into Device'))

if option == 'Upload Config File':
    uploaded_file = st.file_uploader("Choose a Palo Alto Configuration XML file", type=['xml'])
else:
    st.header("Palo Alto Firewall Credentials")
    pan_url = st.text_input("Palo Alto Firewall URL", "https://<firewall-ip>")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

def get_api_key(pan_url, username, password):
    params = {
        'type': 'keygen',
        'user': username,
        'password': password
    }
    response = requests.get(f"{pan_url}/api/", params=params, verify=False)
    if response.status_code == 200:
        data = xmltodict.parse(response.content)
        if 'response' in data and 'result' in data['response'] and 'key' in data['response']['result']:
            return data['response']['result']['key']
    return None

def download_config(pan_url, api_key):
    params = {
        'type': 'export',
        'category': 'configuration',
        'key': api_key,
    }
    response = requests.get(f"{pan_url}/api/", params=params, verify=False)
    if response.status_code == 200:
        return response.content
    return None

def map_address_objects(pa_config):
    addresses = pa_config['config']['shared'].get('address', {}).get('entry', [])
    if not isinstance(addresses, list):
        addresses = [addresses]
    ftnt_addresses = []
    for entry in addresses:
        ftnt_address = {
            'name': entry['@name'],
            'type': 'subnet' if 'ip-netmask' in entry else 'fqdn',
            'value': entry.get('ip-netmask') or entry.get('fqdn')
        }
        ftnt_addresses.append(ftnt_address)
    return ftnt_addresses

def map_service_objects(pa_config):
    services = pa_config['config']['shared'].get('service', {}).get('entry', [])
    if not isinstance(services, list):
        services = [services]
    ftnt_services = []
    for entry in services:
        protocol = entry.get('protocol', {})
        protocol_type = 'tcp' if 'tcp' in protocol else 'udp' if 'udp' in protocol else None
        if protocol_type:
            port = protocol[protocol_type]['port']
            ftnt_service = {
                'name': entry['@name'],
                'protocol_type': protocol_type,
                'port': port
            }
            ftnt_services.append(ftnt_service)
    return ftnt_services

def render_templates(ftnt_addresses, ftnt_services):
    env = Environment(loader=FileSystemLoader('templates'))
    output_files = []

    # Ensure output directory exists
    os.makedirs('output', exist_ok=True)

    # Render address objects
    address_template = env.get_template('address.tf.j2')
    for address in ftnt_addresses:
        output = address_template.render(address)
        file_path = f"output/{address['name']}_address.tf"
        with open(file_path, 'w') as f:
            f.write(output)
        output_files.append(file_path)

    # Render service objects
    service_template = env.get_template('service.tf.j2')
    for service in ftnt_services:
        output = service_template.render(service)
        file_path = f"output/{service['name']}_service.tf"
        with open(file_path, 'w') as f:
            f.write(output)
        output_files.append(file_path)

    return output_files

if st.button("Convert Configuration"):
    if option == 'Upload Config File':
        if uploaded_file is not None:
            st.info("Parsing uploaded configuration...")
            try:
                config_content = uploaded_file.read()
                pa_config = xmltodict.parse(config_content)
                st.success("Configuration parsed successfully.")

                # Mapping configurations
                st.info("Mapping configurations...")
                ftnt_addresses = map_address_objects(pa_config)
                ftnt_services = map_service_objects(pa_config)
                st.success("Configurations mapped successfully.")

                # Generating Terraform files
                st.info("Generating Terraform files...")
                output_files = render_templates(ftnt_addresses, ftnt_services)
                st.success(f"Generated {len(output_files)} Terraform files.")

                # Provide download link
                st.info("Preparing Terraform files for download...")
                shutil.make_archive('terraform_configs', 'zip', 'output')

                with open('terraform_configs.zip', 'rb') as f:
                    st.download_button('Download Terraform Configurations', f, file_name='terraform_configs.zip')

                # Clean up
                shutil.rmtree('output')
                os.remove('terraform_configs.zip')
            except Exception as e:
                st.error(f"An error occurred while processing the configuration: {e}")
        else:
            st.error("Please upload a configuration file.")
    else:
        st.info("Retrieving API key...")
        api_key = get_api_key(pan_url, username, password)
        if api_key:
            st.success("API key retrieved successfully.")
            st.info("Downloading configuration...")
            config_content = download_config(pan_url, api_key)
            if config_content:
                st.success("Configuration downloaded successfully.")
                st.info("Parsing configuration...")
                try:
                    pa_config = xmltodict.parse(config_content)
                    st.success("Configuration parsed successfully.")

                    # Mapping configurations
                    st.info("Mapping configurations...")
                    ftnt_addresses = map_address_objects(pa_config)
                    ftnt_services = map_service_objects(pa_config)
                    st.success("Configurations mapped successfully.")

                    # Generating Terraform files
                    st.info("Generating Terraform files...")
                    output_files = render_templates(ftnt_addresses, ftnt_services)
                    st.success(f"Generated {len(output_files)} Terraform files.")

                    # Provide download link
                    st.info("Preparing Terraform files for download...")
                    shutil.make_archive('terraform_configs', 'zip', 'output')

                    with open('terraform_configs.zip', 'rb') as f:
                        st.download_button('Download Terraform Configurations', f, file_name='terraform_configs.zip')

                    # Clean up
                    shutil.rmtree('output')
                    os.remove('terraform_configs.zip')
                except Exception as e:
                    st.error(f"An error occurred while parsing the configuration: {e}")
            else:
                st.error("Failed to download configuration.")
        else:
            st.error("Failed to retrieve API key. Check your credentials.")
