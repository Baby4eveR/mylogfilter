import os
import time
import logging
import json
from datetime import datetime

#
# f = open("/var/log/audit/test", "a")
# count = 0
# while count < 100:
#     count = count + 20
#     f.write(str(count) + "aaaaaaaaa \n")
#     f.flush()
#     time.sleep(5)
#
# if count == 80:
#     print("get the limit")
#     count = 0
dict_event = {}

exit_code_str = "a"
exit_code_int = int(exit_code_str, base=16)
print(exit_code_int)


def get_parameters(message):
    """

    :return:a0,a1,a2,a3  system call parameters in audit log
    """
    para_list = message.split("a0=")[-1].split()
    para_a0 = para_list[0].lstrip("")
    para_a1 = para_list[1].lstrip("a1=")
    para_a2 = para_list[2].lstrip("a2=")
    para_a3 = para_list[3].lstrip("a3=")
    return para_a0, para_a1, para_a2, para_a3


def test_get_parameter():
    """

    """
    message = """node=localhost.localdomain type=SYSCALL msg=audit(1586944451.637:139191): arch=c000003e 
syscall=42 success=no exit=-13 a0=9 a1=7f19b002b580 a2=10 a3=5 items=0 ppid=1 pid=6943 auid=4294967295 
uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 
comm=72733A6D61696E20513A526567 exe="/usr/sbin/rsyslogd" subj=system_u:system_r:syslogd_t:s0 key=(null)"""
    a0, a1, a2, a3 = get_parameters(message)
    b0 = get_parameters(message)
    if a3 == '1':
        test_para = 1
    if a2 == '10':
        print(test_para)
    print(b0[0])
    assert a0 == "9", "a0 wrong"
    print(a0)
    assert a1 == "7f19b002b580", "a1 wrong"
    assert a2 == "10", "a2 wrong"
    assert a3 == "5", "a3 wrong"


def smart_type_test(message):
    ans = message.startswith("/")
    return ans



# test_get_parameter()


class PersonTest(object):
    def __init__(self, value):
        self.first_name = value

    @property
    def first_name(self):
        print("first name property")
        return self._first_name

    @first_name.setter
    def first_name(self, value):
        print("set first_name value")
        if not isinstance(value, str):
            raise ValueError("expect string type")
        else:
            self._first_name = value

    def test_scope(self):
        sys_num = 0
        if sys_num == 2:
            modify_open()

            def test_open():  # todo:装饰器??????
                pass



def modify_open():
    id = 0
    sysnum = 0
    items = 0
    dict_temp = {
        "id": id,
        "sysnum": sysnum,
        "items": items,

    }
    dict_event["test"] = dict_temp


path = "testpath"
item = "0"
print(path + item)
modify_open()
dict_event["test"][path + item] = "/var/log/audit"
print(dict_event)

logging.basicConfig(level=logging.INFO, filename='sample.txt')

if __name__ == '__main__':
    strtest = "node=localhost.localdomain type=SYSCALL msg=audit(1586944451.637:139191): arch=c000003e " \
              "syscall=42 success=no exit=-13 a0=9 a1=7f19b002b580 a2=10 a3=5 items=0 ppid=1 pid=6943 auid=4294967295 " \
              "uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm=72733A6D61696E20513A526567 " \
              """exe="/usr/sbin/rsyslogd" subj=system_u:system_r:syslogd_t:s0 key=(null)"""
    # with open("/var/log/audit/test1.txt", "r") as f:
    #     while True:
    #         line = f.readline()
    #         print(line)
    #         if line == "":
    #             break
    a = PersonTest(8)
    print(a.first_name)
    a.first_name = "xxxxx"


    class Test(object):
        __name_= "pytest"

        def _set_name(self):
            self._name = "modifyname"

    a = Test()
    # print(a._name)
    a._set_name()
    print(a._name)

    cnt = 0
    items = 0
    id = 0

    logging.info("this is test")
    def my_log(*args, **kwargs):
        dt = datetime.now()
        dtstr = dt.strftime("%Y-%m-%d,%H-%M-%S")
        print("DEBUG:", dtstr, *args, **kwargs)


    my_log = lambda *args: None
    my_log("cnt =", cnt)



    message_dict = {}
    message_line_info = {
        "syscall_num": None,
        "exit_code": None,
        "cwd": None,
        "items_num": None,
    }
    message_dict["12345"] = message_line_info
    message_dict["12345"].update({"PATH1":"/var/temp"})
    print(message_dict)
    my_log("messgae_dict=", message_dict)

    my_json = json.dumps(message_line_info)
    my_json_1 = json.dumps(message_dict)
    logging.info(my_json)
    logging.info("line_num = {},{}".format(cnt, my_json_1))
    str_t = "objtype=create"
    print(str_t.split("objtype")[-1])


    stra = '\\'
    if stra == "\\":
        print(stra)
    strb = stra.lstrip("a")
    print(strb)
    dict_test = {}
    line = 3
    strline = "line="+str(line)
    print(strline)
    f = open("/var/log/audit/test1.txt", "r")

    def read_test():
        for c, l in enumerate(f):
            print(c, l)

    read_test()
    read_test()
    # list = strtest.split(" ", 1)[1]
    # # print(list[0])
    # # print(list[1])
    # print(list)
    # list1 = strtest.split(" ")
    # print(list1)
    # eventid = list1[2].split("(")[1].strip(":").strip(")")
    # print(eventid)
    #
    # f = open("/var/log/audit/audit.log", "r")
    # # f1 = f
    # # f.close()
    # # print(f.readline())
    # # f = open("/var/log/audit/audit.log.1", "r")
    # # print(f1.readline())
    # dict = {}
    # dict[3] = ["12345"]
    # dict[3].append("/usr/sbin")
    # print(dict[3])
    # tu = []
    # tu.append("")
    # a = '3'
    # print(int(a))
    # def read_line():
    #     for c, l in enumerate(f):
    #         print(f.readline())
    #         break
    #
    # read_line()
    # read_line()

    # print(type(f))
    # linecount = 1
    # stack = []
    #
    # def read_cur_eof(file):
    #     count = 0
    #     for c, l in enumerate(file):
    #         global linecount
    #         count = c
    #         line = l
    #         print(linecount + count, line)
    #         # if line is "":
    #         #     print("break")
    #         #     break
    #         # else:
    #         #     print("break")
    #         #     break
    #     print("for end")
    #     linecount = count
    #
    # read_cur_eof(f)
    # time.sleep(30)
    # print("sleep")
    # read_cur_eof(f)

