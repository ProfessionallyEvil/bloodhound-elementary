import argparse
import os
from elementary_data import *
import cmd
import sys
import shlex


class BHDCmd(cmd.Cmd):
    def __init__(self):
        print("Type 'help' for a list of commands.")
        cmd.Cmd.__init__(self)
        self.prompt = 'elementary> '

    def do_exit(self, params):
        print("Exiting...")
        sys.exit(0)

    def help_exit(self):
        print("Exit this program.")

    def do_list(self, paramline):
        params = shlex.split(paramline)
        max_length = 25
        pattern = ".*"

        if len(params) == 0:
            self.help_list()
        elif params[0] not in bh_data.keys():
            print("You can only list these: {}".format(", ".join(bh_data.keys())))
        else:
            if len(params) > 1:
                for param in params[1:]:
                    if param.find("max=") == 0:
                        max_length = int(param[4:])
                    else:
                        pattern = param
            bh_data[params[0]].print_list(pattern, max_length)

    def help_list(self):
        print("List the names of a specified object type.  Syntax: list <{}> [max=<n>] [regex]".format(
            "|".join(bh_data.keys())))

    def do_describe(self, paramline):
        params = shlex.split(paramline)
        if len(params) != 2:
            self.help_describe()
        elif params[0] not in types_singular:
            print("You can only describe these: {}".format(", ".join(types_singular)))
        else:
            data_type = "{}s".format(params[0])
            match = bh_data[data_type].select_one(params[1])
            if match is None:
                print("Could not find a {} object that matches.".format(params[0]))
            else:
                bh_data[data_type].print_details(match)

    def help_describe(self):
        print("Describe the specified object. Syntax: describe <{}> [regex]".format("|".join(types_singular)))

    def do_trace(self, paramline):
        params = shlex.split(paramline)
        if len(params) != 4:
            self.help_trace()
        elif params[0] not in ["user", "computer", "group"] or params[2] not in ["computer", "group", "user"]:
            self.help_trace()
        else:
            source_type = "{}s".format(params[0])
            source_object = bh_data[source_type].select_one(params[1])
            target_type = "{}s".format(params[2])
            target_object = bh_data[target_type].select_one(params[3])
            if source_object is None:
                print("Could not find a {} matching name {}".format(params[0], params[1]))
            elif target_object is None:
                print("Could not find a {} matching name {}".format(params[2], params[3]))
            else:
                print("Tracing paths from {} {} to {} {} (this may take a few moments)".format(params[0], source_object,
                                                                                               params[2],
                                                                                               target_object))
                paths = bh_data[source_type].trace(source_object, target_type, target_object, TraceHistory())
                paths.sort(key=len)
                for path in paths:
                    path_parts = []
                    for item in path:
                        if "users" in item:
                            path_parts.append("user {}".format(item.get("users")))
                        elif "groups" in item:
                            path_parts.append("group {}".format(item.get("groups")))
                        elif "computers" in item:
                            path_parts.append("computer {}".format(item.get("computers")))
                    print("* {}".format(" --> ".join(path_parts)))


    def help_trace(self):
        print(
            "Trace paths from one object to another.  Syntax: trace <{}> <source> <{}> <target>".format("user|computer",
                                                                                                        "computer|group"))

    def do_sessions(self, paramline):
        params = shlex.split(paramline)
        supported = ["user", "computer", "group"]
        if len(params) != 2 or params[0] not in supported:
            self.help_sessions()
        else:
            full_name = bh_data["{}s".format(params[0])].select_one(params[1])
            if full_name is None:
                print("Could not find a {} matching name {}".format(params[0], params[1]))
            elif params[0] == "user":
                print("Finding {} computer sessions:".format(full_name))
                computers = set(bh_sessions["sessions"].for_user(full_name))
                for c in computers:
                    print(c)
            elif params[0] == "group":
                print("Finding computer sessions for all {} users:".format(full_name))
                users = bh_data["groups"].users(full_name)
                for u in users:
                    print("user {}:".format(u))
                    computers = set(bh_sessions["sessions"].for_user(u))
                    for c in computers:
                        print("  {}".format(c))
            elif params[0] == "computer":
                print("Finding all users with sessions on computer {}".format(full_name))
                users = set(bh_sessions["sessions"].for_computer(full_name))
                for u in users:
                    print(u)

    def help_sessions(self):
        supported = ["user", "computer", "group"]
        print("List sessions for the given item.  Syntax:  sessions {} <name>".format("|".join(supported)))

    def do_targets(self, paramline):
        params = shlex.split(paramline)
        if len(params) > 1:
            self.help_targets()
        else:
            if len(params) == 1:
                max = int(params[0])
            else:
                max = 10
            print("TARGET ANALYSIS")
            print("===============")
            print("High Value Groups:")
            for group in bh_data["groups"].high_value(max):
                print("  {}".format(group))

            print("Users with the most sessions:")
            for user in bh_sessions["sessions"].top_users(max):
                sessions = bh_sessions["sessions"].for_user(user)
                print("  {}: {}".format(user, len(sessions)))

            print("Computers with the most sessions:")
            for computer in bh_sessions["sessions"].top_computers(max):
                sessions = bh_sessions["sessions"].for_computer(computer)
                print("  {}: {}".format(computer, len(sessions)))

            print("Users with the most direct local admin access:")
            for user in bh_data["computers"].top_localadmins(max):
                print("  {}: {}".format(user, len(bh_data["computers"].localadmin_for_user(user))))

    def help_targets(self):
        print("List top (10) items by active sessions, access, etc... Syntax: targets [<limit>]")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Bloodhound Elementary - analyzer for bloodhound .json files.')
    parser.add_argument('path', help="The file path to the folder containing the .json files from running Bloodhound.")

    args = parser.parse_args()
    if args.path[-1] == '/':
        path = args.path
    else:
        path = "{}/".format(args.path)

    # Pre-checks - make sure all the files we need exist before we continue.
    if os.path.isdir(path):
        missing_files = False
        for file in ['computers.json', 'domains.json', 'groups.json', 'sessions.json', 'users.json']:
            if not os.path.exists("{}{}".format(path, file)):
                print('It looks like the file {} is missing from your specified folder.'.format(file))
                missing_files = True
        if missing_files:
            print("Cannot continue with missing files!")
        else:
            print("Starting Bloodhound Elementary...")
    else:
        print("The path to your bloodhound files does not exist: {}".format(path))

    bh_data["computers"] = Computers("{}computers.json".format(path))
    bh_data["domains"] = Domains("{}domains.json".format(path))
    bh_data["groups"] = Groups("{}groups.json".format(path))
    bh_data["users"] = Users("{}users.json".format(path))

    types_singular = []
    for key in bh_data.keys():
        types_singular.append(key[:-1])

    bh_sessions["sessions"] = Sessions("{}sessions.json".format(path))

    interpreter = BHDCmd()
    interpreter.cmdloop()
