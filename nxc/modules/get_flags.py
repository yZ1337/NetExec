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
        - userlist: Path to file containing list of usernames.
        """
        self.userlist = module_options.get("USERLIST", None)

        if not self.userlist:
            context.log.error("User list must be provided.")
            raise ValueError("Missing required option: userlist")

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
            context.log.info(f"Connected to {connection.host} as {connection.username}")

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
