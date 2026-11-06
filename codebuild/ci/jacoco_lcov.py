"""Print a JaCoCo XML report as lcov.

Usage: jacoco_lcov.py <jacoco.xml> <source root relative to the repository>

A line counts as hit when its tests covered at least one of its instructions;
JaCoCo keeps no hit counts.
"""
import sys
import xml.etree.ElementTree as ElementTree

report, source_root = sys.argv[1], sys.argv[2]
for package in ElementTree.parse(report).getroot().iter("package"):
    for sourcefile in package.findall("sourcefile"):
        print("SF:%s/%s/%s" % (source_root, package.get("name"), sourcefile.get("name")))
        for line in sourcefile.findall("line"):
            print("DA:%s,%d" % (line.get("nr"), int(line.get("ci")) > 0))
        print("end_of_record")
