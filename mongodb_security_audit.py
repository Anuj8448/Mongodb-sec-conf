import pymongo
import socket
import re
import subprocess
from jinja2 import Environment, FileSystemLoader

# MongoDB URI (Update with your MongoDB credentials)
MONGODB_URI = "mongodb://newAdmin:newPassword123@localhost:27017/mytestdb?authSource=admin"

# 1. Check if Authentication is Enabled
def check_authentication(db):
    try:
        server_status = db.command("serverStatus")
        return "authenticated" in server_status
    except:
        return False

# 2. Check Open Ports
def check_open_ports(host='localhost', ports=[27017]):
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
    return open_ports

# 3. Check if SSL is Enabled
def check_ssl_enabled(client):
    admin_db = client.admin  # Correctly get the admin database
    result = admin_db.command("getCmdLineOpts")
    ssl_enabled = 'sslMode' in result['parsed']['net'] and result['parsed']['net']['sslMode'] == 'requireSSL'
    return ssl_enabled

# 4. Check Password Strength (Example user password is passed)
def check_password_strength(user_password):
    pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
    return bool(pattern.match(user_password))

# 5. Check if IP Binding is Secure
def check_ip_binding(client):
    result = client.admin.command("getCmdLineOpts")
    bind_ip = result['parsed']['net']['bindIp']
    if bind_ip == '0.0.0.0':
        return False  # Insecure: open to all IPs
    return True

# 6. Check if Audit Logging is Enabled
def check_audit_logging_enabled(client):
    result = client.admin.command("getCmdLineOpts")
    audit_logging = 'auditLog' in result['parsed']
    return audit_logging

# 7. Check User Roles for Potential Privilege Escalation
def check_user_roles(db):
    users_info = db.command("usersInfo")
    risky_roles = []
    for user in users_info['users']:
        for role in user['roles']:
            if role['role'] in ['root', 'dbAdminAnyDatabase']:
                risky_roles.append(user['user'])
    return risky_roles

# 8. Check if Replica Set is Configured
def check_replica_set(db):
    try:
        db.admin.command('replSetGetStatus')
        return True
    except:
        return False

# 9. Check MongoDB Version
def check_mongodb_version(db):
    server_info = db.command("buildInfo")
    version = server_info['version']
    return version

# 10. Check if Unnecessary Features (like REST) are Disabled
def check_disabled_features(client):
    result = client.admin.command("getCmdLineOpts")
    rest_enabled = 'rest' in result['parsed']['net'] and result['parsed']['net']['rest']
    return not rest_enabled  # Return True if REST is disabled

# Run Lynis audit
def run_lynis_audit():
    try:
        result = subprocess.run(['sudo', 'lynis', 'audit', 'system', '-Q'], capture_output=True, text=True)
        return result.returncode == 0, result.stdout
    except Exception as e:
        return False, str(e)

# Run Nmap scan
def run_nmap_scan(target='localhost'):
    try:
        result = subprocess.run(['nmap', '-p', '27017', '--script', 'mongodb-databases', target], capture_output=True, text=True)
        return result.returncode == 0, result.stdout
    except Exception as e:
        return False, str(e)

# Run Nikto scan
def run_nikto_scan(target='localhost'):
    try:
        result = subprocess.run(['nikto', '-h', target], capture_output=True, text=True)
        return result.returncode == 0, result.stdout
    except Exception as e:
        return False, str(e)

# Run OpenSCAP audit
def run_openscap_audit(profile='cis', report_path='openscap_report.html', datastream_path='/path/to/datastream.xml'):
    try:
        result = subprocess.run(['oscap', 'xccdf', 'eval', '--profile', profile, '--report', report_path, datastream_path], capture_output=True, text=True)
        return result.returncode == 0, report_path
    except Exception as e:
        return False, str(e)

# Function to Run All Security Checks
def run_security_checks(mongodb_uri):
    client = pymongo.MongoClient(mongodb_uri)
    
    # Use get_default_database to fetch the database from the URI
    db = client.get_default_database()

    results = {
        "authentication": check_authentication(db),
        "ssl_enabled": check_ssl_enabled(client),  # Pass client here
        "ip_binding": check_ip_binding(client),    # Pass client here
        "audit_logging": check_audit_logging_enabled(client),  # Pass client here
        "open_ports": check_open_ports(),
        "user_roles": check_user_roles(db),
        "replica_set": check_replica_set(db),
        "mongodb_version": check_mongodb_version(db),
        "disabled_features": check_disabled_features(client),  # Pass client here
        "password_strength": check_password_strength("Example@123")  # Replace with real user passwords if necessary
    }
    
    results['open_ports'] = ', '.join(map(str, results['open_ports'])) if results['open_ports'] else 'No open ports found.'

    # Integrate external tool results
    results["lynis_status"], results["lynis_summary"] = run_lynis_audit()
    results["nmap_status"], results["nmap_output"] = run_nmap_scan()
    results["nikto_status"], results["nikto_output"] = run_nikto_scan()
    results["openscap_status"], results["openscap_report"] = run_openscap_audit()

    client.close()
    return results

# Generate an HTML Report using Jinja2
def generate_report(results):
    # Load the template from the "templates" folder
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('report_template.html')
    
    report_html = template.render(results=results)

    with open("mongodb_security_report.html", "w") as f:
        f.write(report_html)

# Main execution
if __name__ == "__main__":
    results = run_security_checks(MONGODB_URI)
    generate_report(results)
    print("Security audit completed. Check the report at mongodb_security_report.html")
