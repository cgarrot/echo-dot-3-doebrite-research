import os, glob
ROOT="/home/c<user>/oct_mnt"
p=os.path.join(ROOT,"system/etc/init/init.oobe.rc")
txt=open(p,encoding="utf-8",errors="replace").read()
print(f"=== init.oobe.rc INTÉGRAL ({len(txt)} o) ===")
for i,l in enumerate(txt.split("\n"),1):
    if l.strip(): print(f"{i:3d} {l.rstrip()[:120]}")
print("\n=== où est property_contexts ? ===")
for pat in ["**/property_contexts","**/property_contexts.txt","**/plat_property_contexts"]:
    for f in glob.glob(os.path.join(ROOT,pat), recursive=True)[:5]:
        print("  ", f.replace(ROOT+"/",""), os.path.getsize(f), "o")
