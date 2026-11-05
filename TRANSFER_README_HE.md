# העברת PolicyCompare לרשת העבודה

החבילה מיועדת ל־Windows עם Python 3.12. היא כוללת קוד, בדיקות לא־מקוונות,
דוגמאות סינתטיות, תלויות wheel נעולות, חתימות והוראות.
יעד ה־API הוא CSM 4.25 מול FMC 7.6.5 ומעלה; התאימות לשרתים בפועל טרם נבדקה.
אין בחבילה היסטוריית Git, סביבות Python מקומיות, פרטי הזדהות או נתוני מדיניות אמיתיים.
מחרוזות הזדהות וכתובות בקובצי הבדיקה הן ערכי דמה בלבד.

## בדיקה וקבלה לאחר ההלבנה

יש להעביר את קובץ ה־ZIP ואת קובץ ה־`.zip.sha256` בתהליך הארגוני המאושר.
ב־PowerShell אפשר לחשב את חתימת ה־ZIP לפני חילוץ:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath .\PolicyCompare-Windows-Python312.zip
Get-Content -LiteralPath .\PolicyCompare-Windows-Python312.zip.sha256
```

השם לעיל הוא דוגמה; יש להשתמש בשם החבילה שנמסרה בפועל ולהשוות את ערך
ה־SHA-256 לערך המאושר בתהליך ההעברה. אין להסיק מהתאמה אישור ארגוני.

מחלצים לתיקייה חדשה ונכנסים לתיקיית `PolicyCompare` שנוצרה בתוכה.
מוודאים ש־Python 3.12 זמין, ואז מאמתים את קובצי החבילה:

```powershell
py -3.12 --version
py -3.12 verify_bundle.py
```

צפוי PASS וקוד יציאה 0. ה־manifest כולל SHA-256 וגודל לכל קובץ תוכן,
את מזהה commit המקור ואת גרסאות התלויות. ה־manifest עצמו מוגן באמצעות
חתימת ה־ZIP החיצונית. קובץ חסר, שונה או נוסף שאינו פלט הרצה מוכר יכשיל אימות.
לאחר ההתקנה, תיקיות `.venv`, `reports`, `logs`, `snapshots` ו־`__pycache__`
מוחרגות מאימות הקבצים הנוספים; תוכנן אינו מאושר באמצעות ה־manifest.

## אפשרות א: התקנה ללא כל גישה לרשת

אין צורך בהרשאות מנהל או בהפעלת סקריפט Activate. יוצרים venv חדש:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip --isolated install --disable-pip-version-check --no-cache-dir --no-index --find-links .\wheelhouse --only-binary=:all: --require-hashes -r .\requirements-offline.txt
.\.venv\Scripts\python.exe -m pip --isolated check
```

`--no-index` מונע פנייה למאגר חבילות, ו־`--find-links` מפנה לתלויות המקומיות.
`--require-hashes` דורש את החתימות הנעולות. אין צורך ב־Git, במהדר או בהורדת
קוד מקור במהלך ההתקנה. אין להריץ pip upgrade מהאינטרנט ברשת העבודה.

## אפשרות ב: התקנה דרך Artifactory הארגוני

אפשר להשתמש במקום ה־wheelhouse במאגר pip הפנימי המאושר.
אם כתובת המאגר וה־CA כבר מוגדרים ב־pip לפי הוראות הארגון:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --disable-pip-version-check --no-cache-dir --only-binary=:all: --require-hashes -r .\requirements-offline.txt
.\.venv\Scripts\python.exe -m pip check
```

יש לוודא עם צוות Artifactory שה־index וכל extra-index מוגדרים למאגרים פנימיים
מאושרים בלבד. הפקודה אינה קובעת כתובת בעצמה; היא מסתמכת על ההגדרות הארגוניות.
אם צריך כתובת מפורשת, מחליפים את דוגמת הכתובת הזו בכתובת המאושרת:

```powershell
.\.venv\Scripts\python.exe -m pip install --disable-pip-version-check --no-cache-dir --index-url "https://artifactory.example.invalid/artifactory/api/pypi/approved-python/simple" --only-binary=:all: --require-hashes -r .\requirements-offline.txt
```

הכתובת היא דוגמה שאינה שרת אמיתי. יש לנטרל גם extra-index חיצוני בהגדרות pip.
אם נדרשת תעודת CA ארגונית, משתמשים בהגדרה הארגונית או ב־`--cert` עם קובץ CA
מאושר. אין להשתמש ב־`--trusted-host` כדי לעקוף אימות TLS.
אימות ל־Artifactory יוגדר באמצעות המנגנון הארגוני; אין להכניס שם משתמש,
סיסמה או טוקן לכתובת, לפקודה, ל־requirements או לקבצי הפרויקט.

כל הגרסאות וקובצי ה־wheel המתאימים חייבים להיות זמינים במאגר הפנימי.
חבילה שנבנתה מחדש בארגון עשויה להיות בעלת hash שונה: במקרה כזה ההתקנה
תיעצר. אין להסיר את בדיקת החתימות; יש לאשר נעילה חדשה ולבדוק אותה מחדש,
או להשתמש בקובצי ה־wheel מהחבילה לאחר שאושרו להלבנה.

## בדיקות ללא שרתי Cisco

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -q
.\.venv\Scripts\python.exe compare.py examples/csm.json examples/fmc-network-drift.json --output-dir reports/network-demo
```

כל הבדיקות אמורות לעבור. בדוגמת ההשוואה צפוי קוד יציאה 1: דוח החוקים PASS,
ודוח האובייקטים FAIL בגלל שינוי כתובת סינתטי ידוע. זו התוצאה הנכונה לדוגמה.
בהרצה חוזרת יש לבחור תיקיית פלט חדשה. שני הדוחות נוצרים ב־JSON ובטקסט UTF-8.

בדיקת הגדרות ה־API ללא חיבור, ללא פרטי הזדהות וללא כתיבת נתוני איסוף:

```powershell
.\.venv\Scripts\python.exe lab.py --csm-url https://example.invalid/nbi --fmc-url https://example.invalid --csm-policy example-policy --fmc-policy example-policy --fmc-version 7.6.5 --output-dir reports/preflight-001
```

לא מוסיפים `--connect` בשלב זה. חיבור לשרתי עבודה, ובפרט לייצור, דורש אישור
מפורש לשרתים ולחלון הקריאה. הכלי אינו משנה או פורס חוקים, אך קריאות והזדהות
עשויות להירשם ביומן השרת ולצרוך משאבים. מדריך התרחישים נמצא ב־`LAB_GUIDE.md`.

## תכולה והמשך תחזוקה

`README.md` מסביר את הארכיטקטורה ושלושת שדות ההשוואה.
`DEPENDENCIES.md` מפרט תלויות ורישיונות. `package_transfer.py` הוא כלי בנייה
לשימוש בסביבת הפיתוח בלבד; אין צורך להריצו ברשת העבודה ואין צורך ב־Git להרצת הכלי.
לאחר שינוי קוד או תלויות יש להכין חבילה ו־manifest חדשים ולהריץ בדיקות מחדש.
דוחות ו־snapshots אמיתיים נשארים ברשת העבודה; אין להחזיר אותם ללא צנזור ואישור.

מקור לפקודות ההתקנה והחתימות: [תיעוד pip](https://pip.pypa.io/en/stable/topics/secure-installs/).

## שרתי פיתוח עם תעודה לא מהימנה

אפשר להוסיף `--insecure` לפקודת `lab.py` כדי לדלג על אימות תעודות שני השרתים.
HTTPS עדיין נדרש. אין לצרף לדגל קובצי `--csm-ca` או `--fmc-ca`.
ללא `--connect` עדיין מתבצעת רק בדיקת הגדרות מקומית, גם כשיש `--insecure`.
השימוש בדגל מתועד ב־`run.json` בשדה `tls_verification`.
האופציה הזו אינה משנה את אימות התעודות של pip או של Artifactory.
בחבילה המעודכנת צפויות 121 בדיקות לא־מקוונות.
