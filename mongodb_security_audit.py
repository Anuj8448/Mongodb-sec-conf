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
    except Exception as e:
        return False

# 2. Check if SSL is Enabled
def check_ssl_enabled(client):
    try:
        result = client.admin.command("getCmdLineOpts")
        ssl_enabled = 'sslMode' in result['parsed']['net'] and result['parsed']['net']['sslMode'] == 'requireSSL'
        return ssl_enabled
    except Exception as e:
        return False

# 3. Check if IP Binding is Secure
def check_ip_binding(client):
    try:
        result = client.admin.command("getCmdLineOpts")
        bind_ip = result['parsed']['net']['bindIp']
        return bind_ip != '0.0.0.0'
    except Exception as e:
        return False

# 4. Check if Audit Logging is Enabled
def check_audit_logging_enabled(client):
    try:
        result = client.admin.command("getCmdLineOpts")
        return 'auditLog' in result['parsed']
    except Exception as e:
        return False

# 5. Check Open Ports
def check_open_ports(host='localhost', ports=[27017]):
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
        except Exception as e:
            pass
    return open_ports

# 6. Check User Roles and Password Strength
def check_user_roles_and_password_strength(db, known_passwords):
    try:
        users_info = db.command("usersInfo")
        user_info_with_password_strength = []

        for user in users_info['users']:
            user_name = user['user']
            roles = [role['role'] for role in user['roles']]
            
            # Check if password is in known_passwords dict
            password = known_passwords.get(user_name, None)
            if password:
                password_strength = check_password_strength(password)
            else:
                password_strength = "Unknown (Password not provided)"
            
            user_info_with_password_strength.append({
                "user": user_name,
                "roles": roles,
                "password_strength": "Strong" if password_strength == True else "Weak" if password_strength == False else password_strength
            })

        return user_info_with_password_strength

    except Exception as e:
        return []

# 7. Check if Replica Set is Configured
def check_replica_set(db):
    try:
        db.admin.command('replSetGetStatus')
        return True
    except Exception as e:
        return False

# 8. Check MongoDB Version
def check_mongodb_version(db):
    try:
        server_info = db.command("buildInfo")
        return server_info['version']
    except Exception as e:
        return "Unknown"

# 9. Check if Unnecessary Features (like REST) are Disabled
def check_disabled_features(client):
    try:
        result = client.admin.command("getCmdLineOpts")
        rest_enabled = 'rest' in result['parsed']['net'] and result['parsed']['net']['rest']
        return not rest_enabled
    except Exception as e:
        return False

# 10. Check Password Strength
def check_password_strength(user_password):
    try:
        pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
        return bool(pattern.match(user_password))
    except Exception as e:
        return False

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
        result = subprocess.run(['oscap', 'xccdf', 'eval', '--profile', profile, '--report', report_path, datastream_path],
                                capture_output=True, text=True)
        if result.returncode != 0:
            return False, f"OpenSCAP audit failed! Details: {result.stderr.strip()}"
        return True, report_path
    except Exception as e:
        return False, str(e)

# Function to Run All Security Checks
def run_security_checks(mongodb_uri, known_passwords):
    client = pymongo.MongoClient(mongodb_uri)
    db = client.get_default_database()

    # Perform all checks once and store results
    auth_status = check_authentication(db)
    ssl_status = check_ssl_enabled(client)
    ip_binding_status = check_ip_binding(client)
    audit_logging_status = check_audit_logging_enabled(client)
    open_ports_status = check_open_ports()
    user_roles_info = check_user_roles_and_password_strength(db, known_passwords)
    replica_set_status = check_replica_set(db)
    mongodb_version_status = check_mongodb_version(db)
    disabled_features_status = check_disabled_features(client)

    # Combine results with explanations
    results = {
        "authentication": {
            "status": auth_status,
            "explanation": "MongoDB authentication is enabled, which protects access to the database." if auth_status else "MongoDB authentication is not enabled. Anyone can access the database."
        },
        "ssl_enabled": {
            "status": ssl_status,
            "explanation": "SSL/TLS is enabled, ensuring secure communication." if ssl_status else "SSL/TLS is not enabled, making communication vulnerable."
        },
        "ip_binding": {
            "status": ip_binding_status,
            "explanation": "MongoDB is only accessible from specific IPs." if ip_binding_status else "MongoDB is accessible from any IP, which is insecure."
        },
        "audit_logging": {
            "status": audit_logging_status,
            "explanation": "Audit logging is enabled, which helps track database activities." if audit_logging_status else "Audit logging is not enabled, which reduces traceability."
        },
        "open_ports": {
            "status": open_ports_status,
            "explanation": "Open ports found: " + ', '.join(map(str, open_ports_status)) if open_ports_status else "No risky open ports found."
        },
        "user_roles": {
            "status": user_roles_info,
            "explanation": "The following users have potential privilege risks or weak passwords: " + ', '.join([f"{user['user']} (roles: {', '.join(user['roles'])}, password strength: {user['password_strength']})" for user in user_roles_info]) if user_roles_info else "No risky user roles or weak passwords found."
        },
        "replica_set": {
            "status": replica_set_status,
            "explanation": "Replica set is configured, ensuring database redundancy." if replica_set_status else "Replica set is not configured, which may lead to data loss."
        },
        "mongodb_version": {
            "status": mongodb_version_status,
            "explanation": f"MongoDB version {mongodb_version_status} is running."
        },
        "disabled_features": {
            "status": disabled_features_status,
            "explanation": "Unnecessary features are disabled." if disabled_features_status else "Some unnecessary features like REST API are enabled."
        }
    }

    # External tool results
    lynis_status, lynis_output = run_lynis_audit()
    results["lynis_status"] = {
        "status": lynis_status,
        "explanation": lynis_output if lynis_status else "Lynis audit failed."
    }
    
    nmap_status, nmap_output = run_nmap_scan()
    results["nmap_status"] = {
        "status": nmap_status,
        "explanation": nmap_output if nmap_status else "Nmap scan failed."
    }
    
    nikto_status, nikto_output = run_nikto_scan()
    results["nikto_status"] = {
        "status": nikto_status,
        "explanation": nikto_output if nikto_status else "Nikto scan failed."
    }

    openscap_status, openscap_report = run_openscap_audit()
    results["openscap_status"] = {
        "status": openscap_status,
        "explanation": f"OpenSCAP report generated at {openscap_report}" if openscap_status else "OpenSCAP audit failed."
    }

    client.close()
    return results

# Generate an HTML Report using Jinja2
def generate_report(results):
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('report_template.html')
    
    report_html = template.render(results=results)

    with open("mongodb_security_audit_report.html", "w") as f:
        f.write(report_html)

    return "mongodb_security_audit_report.html"

# Example known passwords dictionary (to be replaced with actual passwords)
known_passwords = {
    "admin": "Admin@123",
    "user1": "WeakPass123",
    # Add other users and passwords here
}

# Example Usage
if __name__ == "__main__":
    results = run_security_checks(MONGODB_URI, known_passwords)
    report_file = generate_report(results)
    print(f"Security audit report generated: {report_file}")
