import sys
import argparse
from impacket.smbconnection import SMBConnection
from io import BytesIO

class NXCModule:
    """
    Module to find root and user flags on a target system via SMB.
    """
    name = "smb_flag_checker"
    description = "Extracts root and user flags from C$ share via SMB."
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
        Define module options.
        - admin: Administrator username.
        - password: Password for administrator user (optional).
        - hash: NTLM hash for administrator user (optional).
        - userlist: Path to file containing list of usernames.
        """
        self.admin = module_options.get("ADMIN", None)
        self.password = module_options.get("PASSWORD", None)
        self.ntlmv1_hash = module_options.get("HASH", None)
        self.userlist = module_options.get("USERLIST", None)

        if not self.admin or not self.userlist:
            context.log.error("Administrator username and user list must be provided.")
            raise ValueError("Missing required options: admin, userlist")

        # Ensure either password or hash is provided
        if not self.password and not self.ntlmv1_hash:
            context.log.error("Either a password or NTLM hash must be provided.")
            raise ValueError("Missing required options: password or hash")

        # Read user list from file
        try:
            with open(self.userlist, "r") as f:
                self.user_list = [line.strip() for line in f.readlines() if line.strip()]
        except Exception as e:
            context.log.error(f"Error reading user list file: {e}")
            raise ValueError("Unable to read user list file")

    def on_login(self, context, connection):
        try:
            smb_conn = connection.conn
            context.log.info(f"Connected to {connection.host} as {self.admin}")

            # List shares to verify access to C$
            shares = smb_conn.listShares()
            for share in shares:
                share_name = share['shi1_netname'][:-1]  # Remove null terminator
                context.log.info(f"Found share: {share_name}")
                if share_name.lower() == "c$":
                    context.log.info(f"Accessing share: {share_name}")
                    self.read_root_flag(context, smb_conn, share_name)
                    self.read_user_flags(context, smb_conn, share_name)
                    break
            else:
                context.log.error("C$ share not found or inaccessible.")

        except Exception as e:
            context.log.error(f"Error: {e}")

    def read_root_flag(self, context, smb_conn, share_name):
        root_flag_path = "Users/Administrator/Desktop/root.txt"
        context.log.info(f"Attempting to read root.txt at {root_flag_path}")

        try:
            buf = BytesIO()
            smb_conn.getFile(share_name, root_flag_path, buf.write)
            content = buf.getvalue().decode().strip()
            context.log.success(f"Found root.txt:\n{content}")
        except Exception as e:
            context.log.error(f"Could not read root.txt: {e}")

    def read_user_flags(self, context, smb_conn, share_name):
        users_path = "Users"
        context.log.info(f"Checking specified user folders in {users_path}...")

        try:
            for user_name in self.user_list:
                desktop_path = f"{users_path}/{user_name}/Desktop"
                try:
                    context.log.info(f"Checking Desktop path for user '{user_name}': {desktop_path}")
                    smb_conn.listPath(share_name, desktop_path)  # Just to check if Desktop exists

                    user_flag_path = f"{desktop_path}/user.txt"
                    context.log.info(f"Attempting to read user.txt at {user_flag_path}")

                    buf = BytesIO()
                    smb_conn.getFile(share_name, user_flag_path, buf.write)
                    content = buf.getvalue().decode().strip()
                    context.log.success(f"Found user.txt in {user_name}'s Desktop:\n{content}")
                except Exception as e:
                    context.log.warning(f"Could not read user.txt in {user_name}'s Desktop: {e}")

        except Exception as e:
            context.log.error(f"Error accessing user directories: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script to find root and user flags on a target system via SMB.")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("-a", "--admin", required=True, help="Administrator username")
    parser.add_argument("-p", "--password", help="Password for administrator user")
    parser.add_argument("-H", "--hash", help="NTLM hash for administrator user")
    parser.add_argument("-u", "--userlist", required=True, help="Path to file containing list of usernames")

    args = parser.parse_args()

    # Read user list from file
    try:
        with open(args.userlist, "r") as f:
            user_list = [line.strip() for line in f.readlines() if line.strip()]
    except Exception as e:
        print(f"[-] Error reading user list file: {e}")
        sys.exit(1)

    # Ensure either password or hash is provided
    if not args.password and not args.hash:
        print("[-] Either a password or NTLM hash must be provided.")
        sys.exit(1)

    # Call find_flags with the provided arguments
    find_flags(args.ip, args.admin, password=args.password, ntlmv1_hash=args.hash, user_list=user_list)
