import paramiko
from paramiko_expect import SSHClientInteraction
import argparse

def restart_tomcat(host, username, password):
    """Restarts Tomcat on a Cisco device."""

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=username, password=password)
    interact = SSHClientInteraction(ssh, timeout=90, display=True)
    command = "utils service restart Cisco Tomcat"

    try:
        interact.expect("admin:")
        interact.send(command)
        interact.expect("admin:", timeout=240)

    except Exception as e:
        print(f"Error: {e}")

    finally:
        ssh.close()

def main():
    parser = argparse.ArgumentParser(description='Restart Cisco Tomcat Service')
    parser.add_argument('-H', '--host', required=True,
                        help='Hostname or IP address of the CUCM server')
    parser.add_argument('-u', '--username', required=True,
                        help='Username for SSH authentication')
    parser.add_argument('-p', '--password', required=True,
                        help='Password for SSH authentication')
    
    args = parser.parse_args()
    
    restart_tomcat(args.host, args.username, args.password)

if __name__ == "__main__":
    main()