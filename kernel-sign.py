from dis import show_code
import errno
from os import remove, system, makedirs, walk, uname
from sys import argv
from shutil import copyfile
import getopt

MODULES_PATH = "/usr/lib/modules/{0}/extra".format(uname().release)
SIGNING_SCRIPT = "/usr/src/kernels/{0}/scripts/sign-file".format(uname().release)
KEY_PATH = None

def print_usage():
  print('TODO: Usage')

def sign_module(base_path, module_name):
  private_key_path = "{0}/MOK.priv".format(KEY_PATH)
  public_key_path = "{0}/MOK.der".format(KEY_PATH)
  module_path = "{0}/{1}".format(base_path, module_name)
  try:
    makedirs("ModuleBackup")
  except OSError as e:
    if e.errno != errno.EEXIST:
      raise
  copyfile(module_path, "ModuleBackup/{0}.bak".format(module_name))
  decompressed_module_path = module_path.split(".xz")[0]
  system("xz -d {0}".format(module_path))
  system('{0} sha512 "{1}" "{2}" "{3}"'.format(SIGNING_SCRIPT, private_key_path, public_key_path, decompressed_module_path))
  system("xz -c {0} > {1}".format(decompressed_module_path, module_path))
  remove(decompressed_module_path)
    

def sign_kernel_modules():
  (_, _, kernel_modules_content) = next(walk(MODULES_PATH))
  kernel_modules = filter(lambda file_name: file_name.endswith(".ko.xz"), kernel_modules_content)
  for module in kernel_modules:
    should_process = input("Found {0}. Do you want to sign that module[Y/n]".format(module)).lower()
    print(should_process)
    while (not (should_process == 'y' or should_process == "no")):
      print("Invalid response!")
      should_process = input("Found {0}. Do you want to sign that module [Y/n]".format(module)).lower()
    if should_process == "y":
      sign_module(MODULES_PATH, module)

def parse_cmd_args():
  global KEY_PATH
  (optlist, _) = getopt.getopt(argv[1:], "", longopts=["key-path="])
  got_key_path = False
  for arg in optlist:
    if arg[0] == '--key-path' and got_key_path:
      print_usage()
      return False
    elif arg[0] == '--key-path':
      got_key_path = True
      KEY_PATH = arg[1]

if __name__ == "__main__":
  parse_cmd_args()
  sign_kernel_modules()
