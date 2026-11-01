# PolicyCompare

הוראות הפעלה מלאות, מיקום התוצאות וארכיטקטורה: [RUN_GUIDE_HE.txt](RUN_GUIDE_HE.txt).

חבילת ההעברה המלאה לרשת העבודה נמצאת ב־[transfer/PolicyCompare-Windows-Python312-TLS-Guide.zip](transfer/PolicyCompare-Windows-Python312-TLS-Guide.zip),
ולצידה [חתימת SHA-256](transfer/PolicyCompare-Windows-Python312-TLS-Guide.zip.sha256).
החבילה כוללת קוד, בדיקות, תלויות להתקנה ללא אינטרנט ומדריך TXT בעברית,
כולל אפשרות `--insecure`. יש להעבירה לפי תהליך ההלבנה הארגוני.

השוואת מדיניות CSM ו־FMC בשני דוחות נפרדים:

1. **חוקים**: שמות Source Objects, שמות Destination Objects ופרוטוקול/פורטי Destination Services.
2. **אובייקטים**: ערכי אובייקטי הרשת והשירותים המופנים מהמדיניות, כולל קבוצות וחברים מקוננים, לפי שם וסוג.

סדר, Action, Enabled ו־Source Ports אינם חלק מההשוואה. התאמה אינה הוכחה לשקילות תעבורה.
יעד התאימות: CSM 4.25 ו־FMC 7.6.5 ומעלה; בדיקה מול שרתים בפועל עדיין נדרשת.

## קובצי הקוד

| קובץ | תפקיד |
| --- | --- |
| `rule.py` | מבנה החוק והמידע על האובייקטים המופנים ממנו |
| `csm.py` | איסוף ופענוח XML מ־CSM |
| `fmc.py` | איסוף ופענוח JSON מ־FMC |
| `compare.py` | שתי ההשוואות והפקת הדוחות |
| `lab.py` | ניהול האיסוף, ההזדהות ושמירת התוצאות |
| `normalization.py` | נרמול כתובות, פרוטוקולים ופורטים |
| `transport.py` | תקשורת HTTPS, זמני המתנה וסגירת חיבורים |
| `response_validation.py` | בדיקת מבנה תשובות API |
| `snapshots.py` | שמירת וטעינת נתונים מנורמלים להשוואה מקומית |
| `errors.py` | סוגי השגיאות של הכלי |

## התקנה

Windows עם Python 3.12. ברשת העבודה pip צריך להיות מוגדר ל־Artifactory הארגוני בלבד.
קובץ התלויות היחיד הוא `requirements.txt`, ובו גרסאות וחתימות קבועות.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --disable-pip-version-check --only-binary=:all: --require-hashes -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
```

אין להזין סודות בקוד או בפקודות ההתקנה. יש להשתמש בהגדרות ההזדהות והתעודות הארגוניות.

## שימוש

בדיקת הגדרות בלבד, ללא חיבור לשרתים:

```powershell
.\.venv\Scripts\python.exe lab.py --csm-url https://example.invalid/nbi --fmc-url https://example.invalid --csm-policy example-policy --fmc-policy example-policy --fmc-version 7.6.5 --output-dir reports/run-001
```

אלה כתובות ושמות לדוגמה. חיבור מתבצע רק עם `--connect`, לאחר אישור מפורש לשרתים.
שמות המשתמשים והסיסמאות נשאלים בזמן ההרצה; הסיסמאות מוסתרות.
אפשר לספק `--csm-ca`, `--fmc-ca`, `--fmc-domain` ו־`--timeout` לפי הצורך.
לשרתי פיתוח עם תעודה עצמית או לא מהימנה אפשר להוסיף `--insecure`.
הדגל מבטל את אימות תעודות שני השרתים להרצה זו בלבד; HTTPS עדיין נדרש.
אין לצרף אליו `--csm-ca` או `--fmc-ca`. השימוש מתועד ב־`run.json`.
ללא הדגל אימות TLS נשאר פעיל. אין שינוי חוקים או פריסה.

אם כבר קיימים קובצי נתונים מנורמלים, אפשר להשוות ללא שרתים:

```powershell
.\.venv\Scripts\python.exe compare.py snapshots/csm.snapshot.json snapshots/fmc.snapshot.json --output-dir reports/offline-001
```

תיקיות הנתונים והדוחות נוצרות כשצריך; הן אינן חלק מקוד המקור.

## תוצאות

`rules_report.json` ו־`rules_report.txt` מציגים חוקים חסרים ועודפים.
`objects_report.json` ו־`objects_report.txt` מציגים שינויי ערכים, אובייקטים חסרים/עודפים וחוקים מושפעים.
באיסוף דרך `lab.py` נשמרים גם snapshots ו־`run.json` עם מצב ההרצה וכשלים.
יש לבחור תיקיית פלט חדשה בכל הרצה; אין דריסת תוצאות קיימות.

קודי יציאה: **0** התאמה, **1** פערים, **2** נתונים לא שלמים או כשל.
מדיניות ריקה דורשת `--allow-empty` מפורש. דוחות ו־snapshots הם מידע תשתיתי ונשארים ברשת המורשית.

FQDN, ICMP, מדיניות CSM מקומית וחריגות אובייקטים לפי מכשיר אינם נתמכים במסלול הנוכחי.
