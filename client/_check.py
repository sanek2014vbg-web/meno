import inspect
import flet as ft

print("Page dialog-related methods:")
print([n for n in dir(ft.Page) if any(k in n for k in ["dialog", "open", "show", "close", "snack", "overlay"])])

print("\nImage sig:")
try:
    print(str(inspect.signature(ft.Image.__init__))[:400])
except Exception as ex:
    print("ERR", ex)

print("\nPage has attribute 'open':", hasattr(ft.Page, "open"))
print("hasattr page.show_dialog:", hasattr(ft.Page, "show_dialog") if hasattr(ft, "Page") else "n/a")
print("hasattr page.close_dialog:", hasattr(ft.Page, "close_dialog") if hasattr(ft, "Page") else "n/a")

# проверим контролы диалогов
for n in ["AlertDialog", "SnackBar"]:
    print("has ft.%s:" % n, hasattr(ft, n))

# где ImageFit?
import flet.controls as ctrl
print("flet.controls attrs with Fit:", [n for n in dir(ctrl) if "Fit" in n][:10])