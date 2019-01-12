import json
import re
from collections import deque

bh_data = {}
bh_sessions = {}


class TraceHistory:

    def __init__(self):
        self._users = set([])
        self._groups = set([])
        self._computers = set([])

    def add_user(self, user):
        self._users.add(user)

    def dedupe_users(self, user_set):
        user_set.difference_update(self._users)
        self._users.update(user_set)

    def add_group(self, group):
        self._groups.add(group)

    def dedupe_groups(self, group_set):
        group_set.difference_update(self._groups)
        self._groups.update(group_set)

    def add_computer(self, computer):
        self._computers.add(computer)

    def dedupe_computers(self, computer_set):
        computer_set.difference_update(self._computers)
        self._computers.update(computer_set)

    def copy(self):
        the_copy = TraceHistory()
        the_copy._users = self._users.copy()
        the_copy._groups = self._groups.copy()
        the_copy._computers = self._computers.copy()
        return the_copy


class BloodhoundObject:

    def __init__(self, type_label, json_file):
        self.type_label = type_label
        print("Loading {}...".format(self.type_label))
        with open(json_file, 'r') as f:
            loaded_json = json.load(f)
            self.data_dict = {}
            for obj in loaded_json.get(type_label, []):
                name = obj.get("Name")
                if name is not None:
                    self.data_dict[name] = obj
            print("  Found {} {} entries.".format(len(self.data_dict), type_label))

    def print_details(self, name):
        if self.data_dict.get(name) is None:
            print("Couldn't find a matching {}".format(self.type_label[:-1]))
        else:
            print("Details for {}:".format(name))
            print("=" * (13 + len(name)))
            print(json.dumps(self.data_dict.get(name), indent=2, sort_keys=True))

    def print_list(self, regex="", max=20):
        obj_list = self.list(regex, max)
        for obj in obj_list:
            print(obj)
        if len(obj_list) == max:
            print("* There may be more, I stopped looking after 20.  Use max=<n> to specify a higher limit.")
        print("Found {} matching {}".format(len(obj_list), self.type_label))

    def list(self, regex="", max=20):
        pattern = re.compile(regex, flags=re.IGNORECASE)
        results = []
        for name in self.data_dict.keys():
            if pattern.search(name) is not None:
                results.append(name)
                if len(results) == max:
                    break
        return results

    def select_one(self, regex=".*", max=25):
        results = self.list(regex, max)
        if len(results) == 0:
            return None
        elif len(results) == 1:
            return results[0]
        else:
            print("Multiple matches for '{}'.  Please select one:".format(regex))
            while True:
                for i in range(len(results)):
                    print("{} - {}".format(i, results[i]))

                selected = input("Which one [type number or 'q' to quit]? ").strip()
                if selected in ["q", "Q"]:
                    return None
                elif selected.isdigit():
                    if int(selected) in range(0, len(results)):
                        return results[int(selected)]

    # The history is a dictionary used to dedupe paths so we don't go around in circles.
    def trace(self, source_name, target_type, target_name, trace_history: TraceHistory):
        return []


class Computers(BloodhoundObject):
    def __init__(self, json_file):
        super().__init__("computers", json_file)
        self.localadmin_users = {}
        for computer_name in self.data_dict.keys():
            for user in self.data_dict.get(computer_name).get("LocalAdmins", []):
                if user.get("Type") == "User":
                    user_name = user.get("Name")
                    if user_name not in self.localadmin_users:
                        self.localadmin_users[user_name] = []
                    self.localadmin_users[user_name].append(computer_name)

    def list_access(self, user, groups=None):
        if groups is None:
            groups = []
        local_admin_access = []
        remote_desktop_access = []
        for computer_name in self.data_dict.keys():
            for local_admin in self.data_dict.get(computer_name).get("LocalAdmins", []):
                if local_admin.get("Name", "") == user and local_admin.get("Type",
                                                                           "") == "User" and computer_name not in local_admin_access:
                    local_admin_access.append(computer_name)
                elif local_admin.get("Name", "") in groups and local_admin.get("Type",
                                                                               "") == "Group" and computer_name not in local_admin_access:
                    local_admin_access.append(computer_name)

            for remote_desktop in self.data_dict.get(computer_name).get("RemoteDesktopUsers", []):
                if remote_desktop.get("Name", "") == user and remote_desktop.get("Type",
                                                                                 "") == "User" and computer_name not in remote_desktop_access:
                    remote_desktop_access.append(computer_name)
                elif remote_desktop.get("Name", "") in groups and remote_desktop.get("Type",
                                                                                     "") == "Group" and computer_name not in remote_desktop_access:
                    remote_desktop_access.append(computer_name)
        return local_admin_access, remote_desktop_access

    def trace(self, source_name, target_type, target_name, trace_history):
        paths = []
        trace_history.add_computer(source_name)

        if source_name == target_name and target_type == "computers":
            return [deque([{"computers": target_name}])]
        else:
            user_sessions = bh_sessions["sessions"].for_computer(source_name)
            trace_history.dedupe_users(user_sessions)

            for user in user_sessions:
                trace_history.add_user(user)
                user_paths = bh_data["users"].trace(user, target_type, target_name, trace_history.copy())
                for up in user_paths:
                    up.appendleft({"computers": source_name})
                    paths.append(up)
            return paths

    def print_details(self, name):
        super().print_details(name)
        print("Active Sessions:")
        for computer in bh_sessions["sessions"].for_computer(name):
            print("  {}".format(computer))

    def top_localadmins(self, max=10):
        top_users = []
        for k in sorted(self.localadmin_users, key=lambda k: len(self.localadmin_users[k]), reverse=True):
            top_users.append(k)
            if len(top_users) >= max:
                break
        return top_users

    def localadmin_for_user(self, user):
        return self.localadmin_users.get(user, [])


class Domains(BloodhoundObject):
    def __init__(self, json_file):
        super().__init__("domains", json_file)

    def print_details(self, name):
        super().print_details(name)
        print("English Translation of Trusts:")
        for trust in self.data_dict.get(name, {}).get("Trusts", []):
            direction = trust.get("TrustDirection", -1)
            if direction == 1:
                print("  {}({}) trusts {}".format(trust.get("TargetName", "target"), trust.get("TrustType", "unknown"),
                                                  name))
            elif direction == 2:
                print("  {} trusts {}({})".format(name, trust.get("TargetName"), trust.get("TrustType", "unknown")))
            elif direction == 3:
                print("  {} and {}({}) trust each other.".format(name, trust.get("TargetName"),
                                                                 trust.get("TrustType", "unknown")))
            elif direction == 0:
                print("  {} has an inactive trust with {}({})".format(name, trust.get("TargetName", "target"),
                                                                      trust.get("TrustType", "unknown")))


class Groups(BloodhoundObject):
    def __init__(self, json_file):
        super().__init__("groups", json_file)

    def for_member(self, member_name, member_type="user"):
        results = []
        for group_name in self.data_dict.keys():
            for member in self.data_dict.get(group_name).get("Members", []):
                if member.get("MemberName", "") == member_name and member.get("MemberType",
                                                                              "") == member_type and group_name not in results:
                    results.append(group_name)
                    super_groups = self.for_member(group_name, "group")
                    for super_group in super_groups:
                        if super_group not in results:
                            results.append(super_group)
                    break
        return results

    def users(self, group_name):
        user_set = set([])
        for member in self.data_dict.get(group_name).get("Members", []):
            if member.get("MemberType", "") == "user":
                user_set.add(member.get("MemberName", ""))
            elif member.get("MemberType", "") == "group":
                user_set.update(self.users(member.get("MemberName")))
        return user_set

    def trace(self, source_name, target_type, target_name, trace_history):
        paths = []
        trace_history.add_group(source_name)

        if target_type == "groups" and target_name == source_name:
            return [deque([{"groups": target_name}])]
        else:
            return paths

    def high_value(self, max=15):
        results = []
        for group_name in self.data_dict.keys():
            if self.data_dict.get(group_name, "").get("Properties", {}).get("highvalue", False):
                results.append(group_name)
                if len(results) == 15:
                    break
        return results


class Sessions:
    def __init__(self, json_file):
        print("Loading sessions...")
        with open(json_file, 'r') as f:
            all_sessions = json.load(f).get("sessions", [])
            self.data_dict = {"users": {}, "computers": {}}
            for session in all_sessions:
                user = session.get("UserName")
                computer = session.get("ComputerName")
                if user is not None and computer is not None:
                    if user not in self.data_dict["users"]:
                        self.data_dict["users"][user] = set([])
                    if computer not in self.data_dict["computers"]:
                        self.data_dict["computers"][computer] = set([])
                    self.data_dict["users"][user].add(computer)
                    self.data_dict["computers"][computer].add(user)

        print("  Found {} session entries.".format(len(all_sessions)))

    def for_user(self, user):
        return self.data_dict["users"].get(user, set([]))

    def for_computer(self, computer):
        return self.data_dict["computers"].get(computer, set([]))

    def top_users(self, max=10):
        top_users = []
        for k in sorted(self.data_dict["users"], key=lambda k: len(self.data_dict["users"][k]), reverse=True):
            top_users.append(k)
            if len(top_users) >= max:
                break
        return top_users

    def top_computers(self, max=10):
        top_computers = []
        for k in sorted(self.data_dict["computers"], key=lambda k: len(self.data_dict["computers"][k]), reverse=True):
            top_computers.append(k)
            if len(top_computers) >= max:
                break
        return top_computers


class Users(BloodhoundObject):
    def __init__(self, json_file):
        super().__init__("users", json_file)

    def print_details(self, name):
        super().print_details(name)
        group_list = bh_data.get("groups").for_member(name)
        if len(group_list) > 0:
            print("Groups:")
            for group in group_list:
                print("  {}".format(group))

        localadmin, remotedesktop = bh_data.get("computers").list_access(name, group_list)

        if len(localadmin) > 0:
            print("Local Admin Access:")
            for computer in localadmin:
                print("  {}".format(computer))

        if len(remotedesktop) > 0:
            print("Remote Desktop Access:")
            for computer in remotedesktop:
                print("  {}".format(computer))

        print("Active Sessions:")
        for computer in bh_sessions["sessions"].for_user(name):
            print("  {}".format(computer))

    def trace(self, source_name, target_type, target_name, trace_history):
        paths = []

        trace_history.add_user(source_name)

        if target_name == source_name and target_type == "users":
            return [deque([{"users": target_name}])]
        else:
            groups = set(bh_data["groups"].for_member(source_name))
            trace_history.dedupe_groups(groups)

            for group in groups:
                trace_history.add_group(group)
                group_paths = bh_data["groups"].trace(group, target_type, target_name, trace_history.copy())
                for gp in group_paths:
                    gp.appendleft({"users": source_name})
                    paths.append(gp)

            local_admin, remote_desktop = bh_data["computers"].list_access(source_name, groups)
            # TODO: currently only looks at local admin.  Could consider remotedesktop and DcomUsers

            computers = set(local_admin)
            trace_history.dedupe_computers(computers)

            for computer in computers:
                trace_history.add_computer(computer)
                computer_paths = bh_data["computers"].trace(computer, target_type, target_name, trace_history.copy())
                for cp in computer_paths:
                    cp.appendleft({"users": source_name, "localadmin": computer in local_admin})
                    paths.append(cp)

        return paths
