import time
from datetime import datetime

import pyinotify
import os

import logging

logger = logging.getLogger(__name__)
logger.setLevel(level=logging.INFO)
handler = logging.FileHandler("log.txt")
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

logger.info("Start print log")
logger.debug("Do something")
logger.warning("Something maybe fail.")




def my_log(*args, **kwargs):
    dt = datetime.now()
    dtstr = dt.strftime("%Y-%m-%d,%H-%M-%S")
    print("DEBUG:", dtstr,  *args, **kwargs)


dict_open_filedsc = {}
cur_event_id = -1
cur_line = -1
dict_event_id = {}
dict_copy_rw = {}



class AbsClass:

    def get_errno(self):
        # print(self.__get_errno())
        return self.g_errno()


def singleton(cls):
    _instance = {}

    def inner():
        if cls not in _instance:
            _instance[cls] = cls()
        return _instance[cls]
    return inner


@singleton
class GetMessageInfo(object):
    def __init__(self, message=""):
        self._message = message
        self._list = self._message.split(" ")

    def set_message(self, message: str):
        if message.startswith("type"):
            self._message = message
        else:
            self._message = message.split(" ", 1)[1]
        self._list = self._message.split(" ")

    @staticmethod
    def get_message_info(message):
        if message.startswith('type'):
            _message = message
        else:
            _message = message.split(' ', 1)[1]
            _message_list = _message.spilt(' ')
        _message_type = _message_list[0].split('=')[-1]
        _event_id = _message_list[1].split("(")[1].strip(":").strip(")")
        if _message_type == "SYSCALL":
            _syscallnum = _message_list[3].split("=")[-1]
        else:
            raise NameError("no syscall attribute")

    def get_message_type(self):
        # GetMessageInfo._init__(message)
        msgtype = self._list[0].split("=")[-1]
        return msgtype

    def get_eventid(self):
        eventid = self._list[1].split("(")[1].strip(":").strip(")")
        return eventid

    def get_syscall_num(self):
        if self.get_message_type() == "SYSCALL":
            syscallnum = self._list[3].split("=")[-1]
        else:
            raise NameError("no syscall attribute")
        return syscallnum

    def get_exit_code(self):
        if self.get_message_type() == "SYSCALL":
            exitcode = self._list[5].split("=")[-1]
        else:
            raise NameError("no syscall attribute")
        return exitcode

    def get_path(self):
        if self.get_message_type() == "PATH":
            path = self._list[3].split("=")[-1].lstrip('"').rstrip('"')
        else:
            raise NameError("no path attribute")
        return path

    def get_cwd(self):
        if self.get_message_type() == "CWD":
            cwd = self._list[2].split("=")[-1].lstrip('"').rstrip('"')
            return cwd

    def get_item_num(self):
        item_num = self._list[10]
        return item_num

    def get_item_index(self):
        item_index = self._list[2].split("=")[-1]
        return item_index

    def get_objtype(self):
        objtype = self._message.split("objtype")[-1].lstrip("=").split(" ")[-1]
        return objtype

    def get_parameters(self):
        """

        :return:a0,a1,a2,a3  system call parameters in audit log
        """
        para_list = self._message.split("a0=")[-1].split()
        para_a0 = para_list[0].lstrip("")
        para_a1 = para_list[1].lstrip("a1=")
        para_a2 = para_list[2].lstrip("a2=")
        para_a3 = para_list[3].lstrip("a3=")
        return para_a0, para_a1, para_a2, para_a3


def process_syscall_read(msg_filter):
    a0, a1, a2, a3 = msg_filter.get_parameters()
    a0_to_int = int(a0, base=16)
    a0_to_str = str(a0_to_int)
    if a0_to_int > 2 and a1 not in dict_copy_rw:    # 0,1,2 zhiwai de miaoshu fu bing jianli neicun quyu he miaoshufu
        dict_temp = {                               # dui ying guanxi
            'read_fd': "-1",
            'write_fd': "-1",
            'read_cnt': 0,
            'write_cnt': 0,
        }
        dict_copy_rw[a1] = dict_temp

    if a0_to_str in dict_open_filedsc:
        dict_copy_rw[a1]['read_fd'] = a0_to_str   # fangzhi du de diyi tiao shi read
        dict_copy_rw[a1]['read_cnt'] = dict_copy_rw[a1]['read_cnt'] + 1
        dict_open_filedsc[a0_to_str]['read_cnt'] = dict_open_filedsc[a0_to_str]['read_cnt'] + 1
        event_id = dict_open_filedsc[a0_to_str]['even_id']
        path = get_abs_path(dict_event_id, event_id)
        if dict_open_filedsc[a0_to_str]['read_cnt'] == 1:
            my_log("read file ,path = {}".format(path))



def process_syscall_write(msg_filter):
    a0, a1, a2, a3 = msg_filter.get_parameters()
    a0_to_int = int(a0, base=16)
    a0_to_str = str(a0_to_int)
    # if a0_to_int > 2 and a1 not in dict_copy_rw:   # fuzhi yinggai xian read zai write
    #     dict_temp = {                              # xian write de bu chu shihua dict_copy_rw
    #         'read_fd': -1,                         # dan du write de ye bu chu shihua
    #         'write_fd': -1,
    #         'read_cnt': 0,
    #         'write_cnt': 0,
    #     }
    #     dict_copy_rw[a1] = dict_temp

    if a0_to_str in dict_open_filedsc:
        dict_copy_rw[a1]['write_fd'] = a0_to_str       # fangzhi du de diyi tiao shi write
        dict_copy_rw[a1]['write_cnt'] = dict_copy_rw[a1]['write_cnt']
        # todo:dict_open_filedsc haisi dict_event_id
        dict_open_filedsc[a0_to_str]['write_cnt'] = dict_open_filedsc[a0_to_str]['write_cnt'] + 1
        event_id = dict_open_filedsc[a0_to_str]['event_id']
        path = get_abs_path(dict_event_id, event_id)
        if dict_open_filedsc[a0_to_str]['read_cnt'] == 1:
            my_log("read file ,path = {}".format(path))

    if dict_copy_rw[a1]['read_cnt'] != 0 and dict_copy_rw[a1]['write_cnt'] == 1:   # read_cnt == write_cnt bu dui
        read_fd = dict_copy_rw[a1]['read_fd']
        write_fd = dict_copy_rw[a1]['write_fd']
        src_path = get_abs_path(dict_event_id, dict_open_filedsc[read_fd]['event_id'])
        dst_path = get_abs_path(dict_event_id, dict_open_filedsc[write_fd]['event_id'])
        my_log("copy file with rw,src_file={} dst_file={}".format(src_path, dst_path))


def process_syscall_close(msg_filter):
    a0, a1, a2, a3 = msg_filter.get_parameters()     # a0 fd
    a0_to_int = int(a0, base=16)
    a0_to_str = str(a0_to_int)
    event_id = dict_open_filedsc[a0_to_str]['event_id']
    dict_open_filedsc.pop(a0)
    dict_event_id.pop(event_id)
    for k, v in dict_copy_rw:
        if v['write_fd'] == a0_to_str:
            v['write_fd'] = "-1"
            v['write_cnt'] = 0
        if v["read_fd"] == a0_to_str:
            v['read_fd'] = "-1"
            v['read_cnt'] = 0
        if v['read_fd'] == "-1" and v['write_fd'] == "-1":
            dict_copy_rw.pop(k)


def process_syscall_rename(msg_filter):
















file_handler = open("/var/log/audit/audit.log")

# def read_eof(file):
#     for c, l in enumerate(file):


def modify_func():
    for c, l in enumerate(file_handler):
        linecount = c
        message = l.strip(" ")
        if message:
            message_handler = GetMessageInfo(message)
            print(linecount, message_handler.get_message_type())
            print(message_handler.get_eventid())
            if message_handler.get_message_type() == "SYSCALL":
                print(message_handler.get_syscall_num())
                print(message_handler.get_exit_code())
            if message_handler.get_message_type() == "PATH":
                print(message_handler.get_path())
        else:
            break
        print("-----------------------")
        # time.sleep(1)


# modify_func()
file_handler.close()

strtest = """node=localhost.localdomain type=SYSCALL msg=audit(1586944451.637:139191): arch=c000003e 
syscall=42 success=no exit=-13 a0=9 a1=7f19b002b580 a2=10 a3=5 items=0 ppid=1 pid=6943 auid=4294967295 
uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 
comm=72733A6D61696E20513A526567 exe="/usr/sbin/rsyslogd" subj=system_u:system_r:syslogd_t:s0 key=(null)"""

strtest1 = """node=localhost.localdomain type=SYSCALL msg=audit(1586939161.507:135157): arch=c000003e 
syscall=2 success=yes exit=3 a0=7f8666fc34d2 a1=80000 a2=1b6 a3=24 items=1 ppid=1 pid=67082 auid=4294967295 
uid=989 gid=983 euid=989 suid=989 fsuid=989 egid=983 sgid=983 fsgid=983 tty=(none) ses=4294967295 
comm="setroubleshootd" exe="/usr/bin/python2.7" subj=system_u:system_r:setroubleshootd_t:s0-s0:c0.c1023 key=(null)"""


# def test_get_msgtype(msg):
#     assert get_msgtype(msg) == "SYSCALL", "not same string"
#
#
# test_get_msgtype(strtest)

modify_event_count = 0
f = open("/var/log/audit/audit.log", "r")
f_w = open("/var/log/audit/temp.log", "a")

''' 未显式close，f指向新的log文件时系统自动回收
    不知道动态文件何时到达eof，出错调试可能困难'''

# fw = open("/var/log/audit/logfilter.txt", "a+")




def get_abs_path(dict_by_id, event_id):
    item_cnt = dict_by_id[event_id]["items"]
    temp_path = dict_by_id[event_id]["path0"]

    if int(item_cnt) == 1:
        if temp_path.startwith("/"):
            abs_path = temp_path
        else:
            abs_path = dict_by_id[event_id]["cwd"] + "/" + temp_path
    else:
        # temp_path = dict_by_id[id]["path1"]
        if dict_by_id[event_id]["path1"].startwith("/"):
            abs_path = dict_by_id[event_id]["path1"]
        else:
            abs_path = temp_path + "/" + dict_by_id[event_id]["path1"]
    return abs_path


def get_oldfile_newfile(dict_by_id, event_id):
    """
    :param dict_by_id:
    :param event_id:
    :return: old file name and new file name
    """
    # todo:完成单元测试
    item_cnt = dict_by_id[event_id]["items"]
    temp_path = dict_by_id[event_id]["path0"]

    if item_cnt == "1":
        if temp_path.startwith("/"):
            old_file = temp_path
            new_file = dict_by_id[event_id]["path1"]
        else:
            old_file = dict_by_id[event_id]["cwd"] + "/" + temp_path
            new_file = dict_by_id[event_id]["cwd"] + "/" + dict_by_id[event_id]["path1"]
    else:
        # temp_path = dict_by_id[id]["path1"]
        if dict_by_id[event_id]["path2"].startwith("/"):
            old_file = dict_by_id[event_id]["path2"]
            new_file = dict_by_id[event_id]["path3"]
        else:
            old_file = temp_path + "/" + dict_by_id[event_id]["path2"]
            new_file = dict_by_id[event_id]["path1"] + dict_by_id[event_id]["path3"]

    return old_file, new_file



'''
dict_copy_rw:{ a1 of read/write : {   "read_fd":          ,
                                      "write_fd":         ,
                                       "read_cnt":         ,
                                       "write_cnt":        ,
                                                        }
                                                                }


dict_open_filedsc{	“文件描述符”：{   
                                    “event id”：     ,
                                    “read_cnt”：     ,
                                    “write_cnt”：    ,
                                                     
                                                },

                    }



dict_event_id :{
                  "event_id" : {  
                                "syscall_num" : syscallnum,
                                "exit_code" : exit_code_num,
                                "items" : item_num,       
                                "path0" :               ,         
                                "path1" :               ,
                                  ......   :            ,              
                                "objtype0" :            ,
                                "objtype1" :            ,   
                                  ......   :            ,       
                                //"read_cnt" :            ,
                                //"write_cnt":            ,
                                                            }
                                                                    }
'''


class myhandler(pyinotify.ProcessEvent):

    def process_IN_MODIFY(self, event):
        # with open("/var/log/audit/audit.log", "r") as file_open:
        #     message_line = file_open.readline()
        global cur_event_id
        global modify_event_count
        modify_event_count += 1
        # print(modify_event_count)
        # while True:
        #     line = f.readline()
        #     fw.write(line + event.pathname)
        my_log(modify_event_count, "process MODIFY event", event.pathname, modify_event_count)
        msg_filter = GetMessageInfo()
        for c, l in enumerate(f):
            '''
            common items of every line in log
            @msg_type:
            @cur_eventid:
            '''
            line = l
            msg_filter.set_message(l)  # todo:danlimoshi ,shixian set fangfa
            msg_type = msg_filter.get_message_type()
            cur_event_id = msg_filter.get_eventid()

            if msg_type == 'SYSCALL':
                syscallnum = msg_filter.get_syscall_num()
                exit_code_num = msg_filter.get_exit_code()

                if syscallnum == '2' and int(exit_code_num) > 0:
                    # global event_dict
                    cur_event_id = msg_filter.get_eventid()
                    item_num = msg_filter.get_item_num()
                    dict_temp = {
                        "syscall_num": syscallnum,
                        "exit_code": exit_code_num,
                        "items": item_num,
                    }
                    dict_event_id[cur_event_id] = dict_temp
                    dict_open_filedsc[exit_code_num]['event_id'] = cur_event_id
                    continue

                if syscallnum == '0':
                    # system call read
                    # Todo:
                    process_syscall_read(msg_filter)
                    continue

                if syscallnum == '1':
                    # todo:system call write
                    a0 = msg_filter.get_parameters()[0]
                    a0_to_int = int(a0, base=16)
                    a0_to_str = str(a0_to_int)
                    if a0_to_str in dict_open_filedsc:
                        cur_event_id = dict_open_filedsc[a0_to_str]
                        path = get_abs_path(dict_event_id, cur_event_id)
                        my_log("write file ,path = {}".format(path))
                    continue

                if syscallnum == '3' and int(exit_code_num) == 0:
                    # todo:system call close
                    a0 = msg_filter.get_parameters()[0]
                    a0_to_int = int(a0, base=16)
                    a0_to_str = str(a0_to_int)
                    if a0_to_str in dict_open_filedsc:
                        cur_event_id = dict_open_filedsc[a0_to_str]
                        dict_open_filedsc.pop(a0_to_str)
                        dict_event_id.pop(cur_event_id)
                    continue

                if syscallnum == '82' and exit_code_num =='0':
                    # todo: system call rename
                    process_syscall_rename()
                    continue

            if msg_type == 'CWD':
                cwd = msg_filter.get_cwd()
                if cur_event_id in dict_event_id:
                    dict_event_id[cur_event_id]["cwd"] = cwd
                continue

            if msg_type == 'PATH':
                # 要考虑path跨文件的情况，读文件最开始就读了path，要判断cur_num是不是-1
                # 通过id判断的方式可以避免跨文件的path问题
                item = msg_filter.get_item_index()
                objtype = msg_filter.get_objtype()
                path = msg_filter.get_path()
                if cur_event_id in dict_event_id:
                    dict_event_id[cur_event_id]["path"+item] = path
                    dict_event_id[cur_event_id]["objtype"+item] = objtype

                if int(item) + 1 == int(dict_event_id[cur_event_id]["items"]):
                    abs_path = get_abs_path(dict_event_id, cur_event_id)
                    if dict_event_id[cur_event_id]['syscall_num'] == "2":
                        str_fmt = "option:open path:{}".format(abs_path)
                        my_log(str_fmt)
                    if dict_event_id[cur_event_id]['syscall_num'] == "82":
                        # todo: 更改输出模式  system call rename ，renameat2也要考虑
                        str_fmt = "option:rename file {} to {} ".format()
                        my_log(str_fmt)
                continue

            if msg_type == 'PROCTITLE':
            #
                if cur_event_id in dict_event_id:
            # TODO:log to file
                    pass



                # if cur_eventid == msg_filter.get_eventid():
                #     path = msg_filter.get_path()
                #     file_dsc = dict_eventid[cur_eventid]
                #     dict_open[file_dsc].append(path)
                #     temp_record = "line_number={},path={}\n" .format(c, dict_open[file_dsc])
                #     f_w.write(temp_record)
                # # TODO:实现get_item，考虑多个路径的情况
                #
                #     my_log("dict_open[]file_dsc]", dict_open[file_dsc])





            print(msg_type)
            print(line)

        # fw.write(line + event.pathname)

        # if(modify_event_count == 20):
        #     print("start to deal event queue", event.pathname)
        #     modify_event_count = 0
        #     print(modify_event_count)
        # modify_func()
        # with open("/var/log/audit/audit.log", "r") as f:
        #     line = f.readline()
        #     print("get here,MODIFY")
        #     print(line)


    def process_IN_CLOSE_WRITE(self, event):
        print("process CLOSE_WRITE event", event.pathname)


    def process_IN_OPEN(self, event):
        print("process OPEN event", event.pathname)


    def process_IN_CREATE(self, event):
        print("process CREATE event", event.pathname)
        global f
        f = open("/var/log/audit/audit.log", "r")


    def process_IN_MOVE(self, event):
        print("process MOVE event", event.pathname)


    def process_IN_DELTE(self, event):
        print("process CREATE event", event.pathname)


# mask = pyinotify.IN_MODIFY | pyinotify.IN_CLOSE_WRITE | pyinotify.IN_OPEN


mask = pyinotify.IN_MODIFY | pyinotify.IN_CREATE
wm = pyinotify.WatchManager()
handler = myhandler()
notifyer = pyinotify.Notifier(wm, handler)
# notifyer = pyinotify.Notifier(wm)


wdd = wm.add_watch("/var/log/audit", pyinotify.ALL_EVENTS, auto_add=True)

# f = open("/var/log/audit/audit.log", "r")
# f.seek(0, 0)
# while True:
#     # f.seek(0, 0)
#     # for line in f:
#     #     print(line)
#     line = f.readline()
#     if line:
#         print(line)
#     # time.sleep(1)


# f.writelines("this is added")
#
# f.seek(0,0)
# for line in f:
#     print(line)
# f.readline()


notifyer.loop()
