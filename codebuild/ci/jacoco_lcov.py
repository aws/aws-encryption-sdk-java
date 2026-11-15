"""Print a JaCoCo XML report as lcov.

Usage: jacoco_lcov.py <jacoco.xml> <source root relative to the repository>

A line counts as hit when its tests covered at least one of its instructions;
JaCoCo keeps no hit counts. A line's branches are listed as its covered
branches (count 1) and then its missed ones (count 0, or - when the line
never ran); JaCoCo does not say which branch is which.
"""
import sys
import xml.etree.ElementTree as ElementTree

report, source_root = sys.argv[1], sys.argv[2]
for package in ElementTree.parse(report).getroot().iter("package"):
    for sourcefile in package.findall("sourcefile"):
        print("SF:%s/%s/%s" % (source_root, package.get("name"), sourcefile.get("name")))
        for line in sourcefile.findall("line"):
            ran = int(line.get("ci")) > 0
            print("DA:%s,%d" % (line.get("nr"), ran))
            covered, missed = int(line.get("cb")), int(line.get("mb"))
            for branch in range(covered + missed):
                taken = "1" if branch < covered else "0" if ran else "-"
                print("BRDA:%s,0,%d,%s" % (line.get("nr"), branch, taken))
        print("end_of_record")
