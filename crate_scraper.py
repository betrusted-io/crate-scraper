#! /usr/bin/env python3
import argparse
import subprocess
from os import listdir
from os.path import isfile, join, isdir

def main():
    parser = argparse.ArgumentParser(description="Scrape and analyze Cargo.lock files")
    parser.add_argument(
        "--cargofile", required=False, help="Cargo lockfile location", type=str, nargs='?', metavar=('cargofile'), const='Cargo.lock'
    )
    parser.add_argument(
        "--download", help="Download source tarballs", action="store_true"
    )
    parser.add_argument(
        "--analyze", help="Analyze downloaded source files", action="store_true"
    )
    args = parser.parse_args()
    if args.download == False and args.analyze == False:
        print("At least one of --download or --analyze should be specified. Doing nothing.")

    if args.cargofile == None:
        cargofile = 'Cargo.lock'
    else:
        cargofile = args.cargofile

    if args.download == True:
        with open(cargofile, 'r') as cf:
            lines = cf.readlines()
            curpkg = None
            curver = None
            source = False
            for line in lines:
                if "[[package]]" in line:
                    if curpkg != None and curver != None and source == True:
                        print("Downloading {} {}".format(curpkg, curver))
                        with open('crates/{}-{}.tgz'.format(curpkg, curver), "wb") as of:
                            subprocess.run(['cargo', 'download', '{}=={}'.format(curpkg, curver)], stdout=of)
                    #elif curpkg == None and curver != None:
                    #    print("package missing")
                    #elif curpkg != None and curver == None:
                    #    print("version missing")
                    curpkg = None
                    curver = None
                    source = False
                if "name =" in line:
                    curpkg = line.split('=')[1].rstrip().replace('"', '').strip()
                if "version =" in line:
                    curver = line.split('=')[1].rstrip().replace('"', '').strip()
                if "source =" in line:
                    if "registry" in line:
                        source = True
                    else:
                        curpkg = None
                        curver = None
                        source = False
                        print("WARNING: github source for {} not downloaded".format(curpkg))

    if args.analyze == True:
        # look for build.rs in the source files
        path = "./crates"
        onlyfiles = [f for f in listdir(path) if isfile(join(path, f))]
        for sourcefile in onlyfiles:
            subprocess.run(['tar', '-C', 'builds/', '-xzf', '{}/{}'.format(path, sourcefile), '--wildcards', '--no-anchored', '*build.rs'])
        buildpath = "./builds"
        onlydirs = [f for f in listdir(buildpath) if isdir(join(buildpath, f))]
        # print(onlydirs)
        with open('builds.rs', 'w') as bf:
            for dir in onlydirs:
                try:
                    with open('{}/{}/build.rs'.format(buildpath, dir), 'r') as buildfile:
                        bf.write("========== build.rs from {} ============================================================\n".format(dir))
                        bf.write(buildfile.read())
                except OSError as e:
                        pass

if __name__ == "__main__":
    main()
    exit(0)
