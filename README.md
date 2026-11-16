# SAS RADIUS لـ MikroTik

هذا المشروع يوفّر خادم RADIUS بسيطًا مع API لإضافة أجهزة MikroTik (NAS) والمستخدمين.

## التشغيل

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SAS_API_KEY = "ضع-مفتاحا-طويلا-هنا"
$env:SAS_ADMIN_USERNAME = "admin"
$env:SAS_ADMIN_PASSWORD = "غيّر-كلمة-المرور-هنا"
$env:SAS_PUBLIC_HOST = "166.122.177.1" # استخدمه فقط إذا كان هذا IP للاستضافة
uvicorn SAS-4:app --host 0.0.0.0 --port 8000
```

محليًا يفتح البرنامج لوحة التحكم على `http://127.0.0.1:8000/`. للوصول الخارجي اضبط `SAS_PUBLIC_HOST` على IP الاستضافة، ويجب أن يكون العنوان مملوكًا لجهاز تشغيل SAS وأن يسمح الجدار الناري بالمنفذ 8000.

عند فتح الرابط ستظهر صفحة تسجيل الدخول. إذا لم تضبط المتغيرات أعلاه فالقيم الافتراضية للتجربة هي `admin` و`admin123`، ويُفضّل تغييرها قبل الاستخدام الفعلي.

إذا كان المنفذ 8000 مستخدمًا، شغّل البرنامج على منفذ آخر:

```powershell
$env:WEB_PORT = "8001"
& "C:/Users/t490/AppData/Local/Programs/Python/Python315/python.exe" .\SAS-4.py
```

افتح UDP 1812 للمصادقة وUDP 1813 للمحاسبة في الجدار الناري. لا تفتحها للإنترنت العام؛ اسمح فقط بعناوين MikroTik.

## إضافة MikroTik كـ NAS

استبدل القيم التالية بعنوان الخادم الذي يشغّل SAS، ومفتاح API، والـ IP المحلي للـ MikroTik:

```powershell
$headers = @{ "X-API-Key" = "ضع-مفتاحا-طويلا-هنا" }
$body = @{ name = "mikrotik-01"; ip_address = "192.168.88.1"; secret = "radius-secret-123" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/nas -Headers $headers -ContentType "application/json" -Body $body
```

## إعداد MikroTik

نفّذ على MikroTik، مع استبدال `192.168.88.10` بعنوان جهاز SAS:

```routeros
/radius add address=192.168.88.10 secret=radius-secret-123 service=ppp,hotspot,login
/radius incoming set accept=yes
/ip hotspot profile set [find] use-radius=yes
/ppp aaa set use-radius=yes accounting=yes interim-update=5m
```

يجب أن يكون `ip_address` في API هو عنوان MikroTik الذي سيظهر منه طلب RADIUS، وأن يطابق عنوان المصدر الذي يصل إلى خادم SAS.

## إضافة مستخدم

```powershell
$headers = @{ "X-API-Key" = "ضع-مفتاحا-طويلا-هنا" }
$body = @{ username = "user1"; password = "StrongPassword!123" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/users -Headers $headers -ContentType "application/json" -Body $body
```

## دخول المشترك عبر RADIUS

بعد إضافة المستخدم من صفحة **المشتركين**، اجعل MikroTik يرسل مصادقة PPPoE أو Hotspot إلى SAS:

```routeros
/radius add address=IP_OF_SAS_SERVER secret=radius-secret-123 service=ppp,hotspot
/ppp aaa set use-radius=yes accounting=yes interim-update=5m
/ip hotspot profile set [find] use-radius=yes
```

عند دخول المشترك، يرسل MikroTik اسم المستخدم وكلمة المرور إلى SAS على UDP 1812. إذا كانت البيانات صحيحة يرد SAS بـ `Access-Accept`، وعندها يسمح MikroTik للمشترك بالدخول. المحاسبة ترسل إلى UDP 1813.

لـPPPoE استخدم نوع المصادقة PAP أثناء الاختبار. يجب أن يكون عنوان `IP_OF_SAS_SERVER` قابلًا للوصول من MikroTik، وأن يكون الـShared Secret مطابقًا للقيمة التي أضفت بها جهاز NAS.

## إدارة IP Pool

من صفحة **بـولات MikroTik** أضف الراوتر أولًا من صفحة **الحسابات و NAS** عبر MikroTik API، ثم اختر الراوتر وأدخل اسم الـPool ومدى العناوين، مثل `10.10.10.2-10.10.10.254`. سيُنشأ الـPool مباشرة على MikroTik عبر API.

بعد إنشائه سيظهر اسم الـPool في نموذج إضافة المشترك. عند نجاح RADIUS يرسل SAS الخاصية `Framed-Pool`، ويستطيع MikroTik توزيع العنوان من ذلك الـPool.

## سكربت ربط MikroTik

من صفحة **الحسابات و NAS** أدخل عنوان MikroTik وبيانات MikroTik API، ثم أدخل عنوان جهاز SAS وRADIUS Shared Secret. بعد نجاح الفحص يعرض النظام سكربت RouterOS جاهزًا للنسخ إلى Terminal في MikroTik. يجب أن يكون عنوان `host` هو عنوان MikroTik، بينما `radius_address` هو عنوان جهاز SAS.

نقطة الفحص: `GET /health`. عرض الأجهزة: `GET /nas` مع ترويسة `X-API-Key`.

> هذه نسخة أساس للمصادقة PAP والمحاسبة. قبل الإنتاج أضف HTTPS للـ API، نسخًا احتياطية لقاعدة البيانات، وتقييد الجدار الناري، ويفضل تشغيلها خلف خدمة Windows أو Docker.
