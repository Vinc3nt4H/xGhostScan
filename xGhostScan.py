#coding: utf-8
import os, os.path 
import subprocess

ST_FAST = "fast"
ST_DEEP = "deep"

def cr():
    print "#########################################"
    print "#\txGhost scan on MacOS"
    print "#\t  Code by 没羽@alibaba"
    print "#\tsupport XcodeGhost, UnityGhost(to be update) malcode scan."
    print "#########################################"

def run_cmd(cmd):
    b = True
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, stderrdata = p.communicate()
    if p.returncode != 0:
        b = False
        output = stderrdata
    return b,output

def isElf(filepath):
    ret = False
    cmd = 'file \"' + filepath + '\" | grep "Mach-O object"'
    b,c = run_cmd(cmd)
    if b and c != "":
        ret = True
    return ret

def scan_fast(xpath):
    ret = False; result = []
    xmal_filepath = xpath+'/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/Library/Frameworks/CoreServices.framework/CoreService'
    xconfig_path = xpath+'/Contents/PlugIns/Xcode3Core.ideplugin/Contents/SharedSupport/Developer/Library/Xcode/Plug-ins/CoreBuildTasks.xcplugin/Contents/Resources/Ld.xcspec'

    if os.path.exists(xmal_filepath):
        ret = True
        result.append(xmal_filepath+", (remove this file)")
    cmd = 'cat \"' + xconfig_path + '\" | grep CoreServices.framework/CoreService'
    #c = os.popen(cmd ,'r').read()
    b,c = run_cmd(cmd)
    if b and c != '':
        ret = True
        result.append(xconfig_path+", (modify 'force_load' in this file)")

    return ret, result 

C2C_SRV = "icloud-analysis.com|icloud-diagnostics.com"
def scan_deep(xpath):
    ret = False; result = []

    print '  please wait ... ...'

    for it in os.walk(xpath):
        for ii in it[2]:
            filename = '%s/%s' % (it[0],ii)
            if not os.path.isfile(filename): continue
            if isElf(filename):
                cmd = 'strings \"' + filename + '\" | grep -E \"' + C2C_SRV + '\"'
                #c = os.popen(cmd ,'r').read()
                b,c = run_cmd(cmd)
                if b and c != "":
                    ret = True
                    result.append(filename+", (remove this file)")

    return ret, result

def main(stype, xpath):
    if stype==ST_FAST:
        ret,result = scan_fast(xpath)
    elif stype==ST_DEEP:
        ret,result = scan_deep(xpath)

    print 'Scan Result:'
    if ret:
        print ' Found XcodeGhost. Please see file(s):'
        for f in result:
            print '  %s' % f
    else:
        print ' Not Found XcodeGhost.'

if __name__ == '__main__':
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option("-t", "--type", dest="type", help="scan type: fast | deep, \n\tdefault is fast")
    parser.add_option("-p", "--path", dest="path", help="Xcode path: like /Applications/Xcode.app/, \n\tdefault is /Applications/Xcode.app/")
    (cmdln_options, args) = parser.parse_args()
    cr()
    stype = cmdln_options.type
    if stype is None:
        stype = 'fast'
    elif stype not in [ST_FAST, ST_DEEP]:
        print 'Error: error scan type.'
        exit
    xpath = cmdln_options.path
    if xpath is None:
        xpath = '/Applications/Xcode.app/'

    print ' scanning... \n scan type: %s, Xcode folder: %s' % (stype, xpath)
    main(stype, xpath)


