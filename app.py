import streamlit as st
import requests
import xmltodict
from jinja2 import Environment, FileSystemLoader
import os
import shutil
import traceback

# Suppress SSL warnings for demo purposes
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Update the title and add a subtitle
st.title("AI Platform Firewall Generator")
st.subheader("Palo Alto Firewall to Terraform FortiOS Converter")

# Display the image under the subtitle
image_path = os.path.join('images', 'image.png')
st.image(image_path)

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
    ftnt_addresses = []
    config = pa_config.get('config') or {}
    shared = config.get('shared') or {}
    address = shared.get('address') or {}
    entries = address.get('entry') or []
    if not isinstance(entries, list):
        entries = [entries] if entries else []

    for entry in entries:
        ftnt_address = {
            'name': entry.get('@name', 'unknown'),
            'type': 'subnet' if 'ip-netmask' in entry else 'fqdn',
            'value': entry.get('ip-netmask') or entry.get('fqdn', 'unknown'),
            'description': entry.get('description', '')
        }
        ftnt_addresses.append(ftnt_address)
    return ftnt_addresses

def map_address_groups(pa_config):
    ftnt_address_groups = []
    config = pa_config.get('config') or {}
    shared = config.get('shared') or {}
    address_group = shared.get('address-group') or {}
    entries = address_group.get('entry') or []
    if not isinstance(entries, list):
        entries = [entries] if entries else []

    for entry in entries:
        members = entry.get('static', {}).get('member', [])
        if not isinstance(members, list):
            members = [members] if members else []
        ftnt_group = {
            'name': entry.get('@name', 'unknown'),
            'members': members,
            'description': entry.get('description', '')
        }
        ftnt_address_groups.append(ftnt_group)
    return ftnt_address_groups

def map_service_objects(pa_config):
    ftnt_services = []
    config = pa_config.get('config') or {}

    # Shared services
    shared = config.get('shared') or {}
    service = shared.get('service') or {}
    entries = service.get('entry') or []
    if not isinstance(entries, list):
        entries = [entries] if entries else []
    ftnt_services.extend(process_service_entries(entries))

    # Services in devices
    devices = config.get('devices', {}).get('entry', [])
    if not isinstance(devices, list):
        devices = [devices] if devices else []
    for device in devices:
        vsys_entries = device.get('vsys', {}).get('entry', [])
        if not isinstance(vsys_entries, list):
            vsys_entries = [vsys_entries] if vsys_entries else []
        for vsys in vsys_entries:
            service = vsys.get('service') or {}
            entries = service.get('entry') or []
            if not isinstance(entries, list):
                entries = [entries] if entries else []
            ftnt_services.extend(process_service_entries(entries))
    return ftnt_services

def process_service_entries(entries):
    ftnt_services = []
    for entry in entries:
        protocol = entry.get('protocol', {})
        protocol_type = 'tcp' if 'tcp' in protocol else 'udp' if 'udp' in protocol else None
        if protocol_type:
            port = protocol[protocol_type].get('port', 'unknown')
            ftnt_service = {
                'name': entry.get('@name', 'unknown'),
                'protocol_type': protocol_type,
                'port': port
            }
            ftnt_services.append(ftnt_service)
    return ftnt_services

def map_security_rules(pa_config):
    ftnt_rules = []
    devices = pa_config.get('config', {}).get('devices', {}).get('entry', [])
    if not isinstance(devices, list):
        devices = [devices] if devices else []

    for device in devices:
        vsys_entries = device.get('vsys', {}).get('entry', [])
        if not isinstance(vsys_entries, list):
            vsys_entries = [vsys_entries] if vsys_entries else []

        for vsys in vsys_entries:
            rules = vsys.get('rulebase', {}).get('security', {}).get('rules', {}).get('entry', [])
            if not isinstance(rules, list):
                rules = [rules] if rules else []
            for rule in rules:
                ftnt_rule = {
                    'name': rule.get('@name', 'unknown'),
                    'source_zones': rule.get('from', {}).get('member', []),
                    'destination_zones': rule.get('to', {}).get('member', []),
                    'source_addresses': rule.get('source', {}).get('member', []),
                    'destination_addresses': rule.get('destination', {}).get('member', []),
                    'applications': rule.get('application', {}).get('member', []),
                    'services': rule.get('service', {}).get('member', []),
                    'action': rule.get('action', 'allow'),
                    'description': rule.get('description', '')
                }
                # Ensure lists
                for key in ['source_zones', 'destination_zones', 'source_addresses', 'destination_addresses', 'applications', 'services']:
                    if not isinstance(ftnt_rule[key], list):
                        ftnt_rule[key] = [ftnt_rule[key]] if ftnt_rule[key] else []
                ftnt_rules.append(ftnt_rule)
    return ftnt_rules

def map_nat_rules(pa_config):
    ftnt_nat_rules = []
    devices = pa_config.get('config', {}).get('devices', {}).get('entry', [])
    if not isinstance(devices, list):
        devices = [devices] if devices else []

    for device in devices:
        vsys_entries = device.get('vsys', {}).get('entry', [])
        if not isinstance(vsys_entries, list):
            vsys_entries = [vsys_entries] if vsys_entries else []

        for vsys in vsys_entries:
            rules = vsys.get('rulebase', {}).get('nat', {}).get('rules', {}).get('entry', [])
            if not isinstance(rules, list):
                rules = [rules] if rules else []
            for rule in rules:
                ftnt_rule = {
                    'name': rule.get('@name', 'unknown'),
                    'source_zones': rule.get('from', {}).get('member', []),
                    'destination_zones': rule.get('to', {}).get('member', []),
                    'source_addresses': rule.get('source', {}).get('member', []),
                    'destination_addresses': rule.get('destination', {}).get('member', []),
                    'service': rule.get('service', 'any'),
                    'source_translation': rule.get('source-translation', {}),
                    'destination_translation': rule.get('destination-translation', {}),
                    'description': rule.get('description', ''),
                    'to_interface': rule.get('to-interface', '')
                }
                # Ensure lists
                for key in ['source_zones', 'destination_zones', 'source_addresses', 'destination_addresses']:
                    if not isinstance(ftnt_rule[key], list):
                        ftnt_rule[key] = [ftnt_rule[key]] if ftnt_rule[key] else []
                ftnt_nat_rules.append(ftnt_rule)
    return ftnt_nat_rules

# Updated render_templates function
def render_templates(ftnt_addresses, ftnt_address_groups, ftnt_services, ftnt_security_rules, ftnt_nat_rules):
    env = Environment(loader=FileSystemLoader('templates'))
    output_files = []
    output_contents = []

    # Ensure output directory exists
    os.makedirs('output', exist_ok=True)

    # Render address objects
    address_template = env.get_template('address.tf.j2')
    for address in ftnt_addresses:
        output = address_template.render(address=address)
        file_name = f"{address['name']}_address.tf"
        file_path = f"output/{file_name}"
        with open(file_path, 'w') as f:
            f.write(output)
        output_files.append(file_path)
        output_contents.append({'file_name': file_name, 'content': output})

    # Render address groups
    address_group_template = env.get_template('address_group.tf.j2')
    for group in ftnt_address_groups:
        output = address_group_template.render(group=group)
        file_name = f"{group['name']}_address_group.tf"
        file_path = f"output/{file_name}"
        with open(file_path, 'w') as f:
            f.write(output)
        output_files.append(file_path)
        output_contents.append({'file_name': file_name, 'content': output})

    # Render service objects
    service_template = env.get_template('service.tf.j2')
    for service in ftnt_services:
        output = service_template.render(service=service)
        file_name = f"{service['name']}_service.tf"
        file_path = f"output/{file_name}"
        with open(file_path, 'w') as f:
            f.write(output)
        output_files.append(file_path)
        output_contents.append({'file_name': file_name, 'content': output})

    # Render security policies
    policy_template = env.get_template('policy.tf.j2')
    for policy in ftnt_security_rules:
        output = policy_template.render(policy=policy)
        file_name = f"{policy['name']}_policy.tf"
        file_path = f"output/{file_name}"
        with open(file_path, 'w') as f:
            f.write(output)
        output_files.append(file_path)
        output_contents.append({'file_name': file_name, 'content': output})

    # Render NAT rules
    nat_template = env.get_template('nat.tf.j2')
    for nat_rule in ftnt_nat_rules:
        output = nat_template.render(nat_rule=nat_rule)
        file_name = f"{nat_rule['name']}_nat.tf"
        file_path = f"output/{file_name}"
        with open(file_path, 'w') as f:
            f.write(output)
        output_files.append(file_path)
        output_contents.append({'file_name': file_name, 'content': output})

    return output_files, output_contents

if st.button("Convert Configuration"):
    try:
        if option == 'Upload Config File':
            if uploaded_file is not None:
                st.info("Parsing uploaded configuration...")
                config_content = uploaded_file.read()
                pa_config = xmltodict.parse(config_content)

                # Mapping configurations
                st.info("Mapping configurations...")
                ftnt_addresses = map_address_objects(pa_config)
                ftnt_address_groups = map_address_groups(pa_config)
                ftnt_services = map_service_objects(pa_config)
                ftnt_security_rules = map_security_rules(pa_config)
                ftnt_nat_rules = map_nat_rules(pa_config)
                st.success("Configurations mapped successfully.")

                # Generating Terraform files
                st.info("Generating Terraform files...")
                output_files, output_contents = render_templates(
                    ftnt_addresses,
                    ftnt_address_groups,
                    ftnt_services,
                    ftnt_security_rules,
                    ftnt_nat_rules
                )
                st.success(f"Generated {len(output_files)} Terraform files.")

                # Display the Terraform outputs
                st.info("Displaying Terraform outputs...")
                for item in output_contents:
                    st.markdown(f"### {item['file_name']}")
                    st.code(item['content'], language='terraform')

                # Provide download link
                st.info("Preparing Terraform files for download...")
                shutil.make_archive('terraform_configs', 'zip', 'output')

                with open('terraform_configs.zip', 'rb') as f:
                    st.download_button('Download Terraform Configurations', f, file_name='terraform_configs.zip')

                # Clean up
                shutil.rmtree('output')
                os.remove('terraform_configs.zip')
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
                    pa_config = xmltodict.parse(config_content)

                    # Mapping configurations
                    st.info("Mapping configurations...")
                    ftnt_addresses = map_address_objects(pa_config)
                    ftnt_address_groups = map_address_groups(pa_config)
                    ftnt_services = map_service_objects(pa_config)
                    ftnt_security_rules = map_security_rules(pa_config)
                    ftnt_nat_rules = map_nat_rules(pa_config)
                    st.success("Configurations mapped successfully.")

                    # Generating Terraform files
                    st.info("Generating Terraform files...")
                    output_files, output_contents = render_templates(
                        ftnt_addresses,
                        ftnt_address_groups,
                        ftnt_services,
                        ftnt_security_rules,
                        ftnt_nat_rules
                    )
                    st.success(f"Generated {len(output_files)} Terraform files.")

                    # Display the Terraform outputs
                    st.info("Displaying Terraform outputs...")
                    for item in output_contents:
                        st.markdown(f"### {item['file_name']}")
                        st.code(item['content'], language='terraform')

                    # Provide download link
                    st.info("Preparing Terraform files for download...")
                    shutil.make_archive('terraform_configs', 'zip', 'output')

                    with open('terraform_configs.zip', 'rb') as f:
                        st.download_button('Download Terraform Configurations', f, file_name='terraform_configs.zip')

                    # Clean up
                    shutil.rmtree('output')
                    os.remove('terraform_configs.zip')
                else:
                    st.error("Failed to download configuration.")
            else:
                st.error("Failed to retrieve API key. Check your credentials.")
    except Exception as e:
        st.error(f"An error occurred during processing: {e}")
        st.text(traceback.format_exc())
