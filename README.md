# PolicyCompare

כלי לקריאה ולהשוואה של מדיניות CSM ו־FMC. המטרה היא שתי בדיקות נפרדות:
התאמת שלושת שדות החוק, ולאחר מכן התאמת ערכי האובייקטים המופנים מהמדיניות.
הכלי אינו משנה חוקים או מבצע פריסה. ייבוא קובץ Python אינו מתחבר לשרת.

## המבנה

- `rule.py`: מחלקת `Rule`, הכוללת את שלושת שדות ההשוואה ומידע לדוח האובייקטים.
- `csm.py`: לקוח CSM XML, איסוף כל דפי המדיניות ופענוח חוקים ואובייקטים.
- `fmc.py`: לקוח FMC REST, איסוף כל הדפים ופענוח חוקים ואובייקטים.
- `compare.py`: השוואת מערכי החוקים, השוואת ערכי האובייקטים והפקת שני דוחות.
- `normalization.py`: נרמול כתובות, פרוטוקולים ופורטים.
- `transport.py`: תקשורת HTTP עם TLS, זמני המתנה וטיפול מוגבל ב־429.
- `response_validation.py`: בדיקת מבנה רשימות ומזהים בתשובות API.
- `snapshots.py`: שמירה וטעינה של נתונים מנורמלים לצורך השוואה ללא שרתים.
- `lab.py`: בדיקת הגדרות מקומית, ובהרצה מפורשת — איסוף, השוואה וסגירת החיבורים.
- `errors.py`: שגיאות API ושגיאות אימות נתונים.
- `tests/`: בדיקות מקומיות עם תשובות מדומות וכתובות שמורות לדוגמאות.

## שלב ראשון: דוח חוקים

מפתח ההתאמה מכיל **רק**:

1. שמות Source Objects.
2. שמות Destination Objects.
3. הפרוטוקול וטווחי הפורטים של Destination Services, לאחר פתיחת קבוצות שירותים.

ההנחה היא ששמות האובייקטים נשמרו במעבר בין המערכות. השמות מושווים בדיוק,
כולל אותיות גדולות וקטנות. שמות שונים עם אותן כתובות אינם אותו חוק.
TCP/53 שונה מ־UDP/53. טווחים חופפים או רצופים באותו פרוטוקול מתאחדים.
שמות אובייקטי השירות אינם חלק ממפתח החוק: הפרוטוקולים והפורטים שלהם כן.

סדר חוקים, מספרי חוקים, Action, Enabled, Zones, משתמשים, זמני הפעלה ו־Source
Ports אינם נבדקים ואינם מכשילים בדיקה בגלל הבדל בהם. `action` ו־`enabled`
נותרו במחלקה לצורכי תאימות לקוד קודם, אך מנגנון ההשוואה אינו משתמש בהם.
תוצאה תואמת אינה קביעה לגבי התנהגות חומת האש בפועל.

`find_gaps(csm_rules, fmc_rules)` שומר על הממשק המקורי ומחזיר רשימת מופעי
`Rule` שקיימים ב־CSM וחסרים ב־FMC. `compare_rules` בודק את שני הכיוונים.
חתימות כפולות אינן פער, ופיצול חוק אחד למספר חוקים אינו נחשב שקילות.

ערכי רשת מפורשים שאינם אובייקטים מנורמלים ומקבלים מזהה פנימי שמתחיל
ב־`@literal:`; רשימת רשתות חסרה או ריקה בלקוח API מיוצגת כ־`@any`.
שמות שמתחילים ב־`@` שמורים לייצוגים פנימיים ואינם שמות אובייקטים רגילים.
אין להסיק שקילות בין אובייקט בעל שם לבין ערך מפורש רק מפני שערכיהם זהים.

## שלב שני: דוח אובייקטים

`compare_objects` מתאים אובייקטים לפי **סוג ושם**, ומשווה את הערכים בפועל:

- רשת: מארח, CIDR/מסכה, טווח כתובות או קבוצה מקוננת.
- שירות: פרוטוקול ופורטי יעד, כולל קבוצות מקוננות.
- רשימת פורטים של CSM: טווחים ללא פרוטוקול עצמאי.

נבדקים רק אובייקטים שמופנים מהמדיניות, כולל כל חבר מקונן שהגיעו אליו
דרך קבוצה. אובייקטים אחרים בספריית השרת אינם נאספים לדוח. קבוצה מושווית
לפי איחוד ערכיה; כל חבר בעל שם נבדק גם בנפרד, כך ששינוי בחבר לא יוסתר
מפני שאובייקט אחר בקבוצה כבר מכסה את אותן כתובות או פורטים.
המבנה ההיררכי כשלעצמו אינו מפתח השוואה.

הדוח כולל אובייקטים חסרים ב־FMC, עודפים ב־FMC, ערכים שונים והחוקים המושפעים
בכל צד. אובייקט רשת ושירות בעלי אותו שם הם שני אובייקטים נפרדים.
אם CSM Port List הומר ב־FMC לאובייקט שירות בעל פרוטוקול, הוא יופיע כחסר/עודף
לפי הסוג, בלי להמציא התאמה שלא הוגדרה.

שינוי כתובת תחת אותו שם יכול לתת `PASS` בדוח החוקים ו־`FAIL` בדוח האובייקטים.
שינוי פורט של שירות מופנה יכול להכשיל את שני הדוחות. שגיאת פתרון אובייקט רשת
לא מוחקת את שם האובייקט מהחוק: דוח החוקים עדיין יכול להסתיים, ודוח האובייקטים
יהיה `INDETERMINATE`. כשל בפתרון שירות יעד מונע גם את השוואת שירותי החוק.

## התקנה ובדיקות

Python 3.12 ומעלה, עם Requests:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m unittest discover -s tests -v
```

במחשב הנוכחי Python המערכת לא הצליח ליצור סביבה מלאה. הבדיקות הורצו
באמצעות סביבת Python המצורפת ל־Codex ותלויות מקומיות בתיקיית `.deps`,
שאינה מנוהלת ב־Git:

```powershell
$env:PYTHONPATH = "$PWD\.deps"
$testPython = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
& $testPython -m unittest discover -s tests -v
```

## הרצה מקומית ושני הדוחות

```powershell
python compare.py snapshots/csm.json snapshots/fmc.json --output-dir reports/run-001
```

אפשר לנסות ללא שרתים בעזרת דוגמאות סינתטיות מנוהלות ב־Git:

```powershell
python compare.py examples/csm.json examples/fmc-network-drift.json --output-dir reports/network-demo
python compare.py examples/csm.json examples/fmc-service-drift.json --output-dir reports/service-demo
```

בדוגמה הראשונה דוח החוקים עובר ודוח האובייקטים מציג שינוי כתובת.
בדוגמה השנייה TCP הוחלף ב־UDP באותו פורט, ושני הדוחות מציגים פערים.
אלה נתוני דוגמה בלבד, ללא פרטי ארגון.

המסוף מחזיר שני דוחות נפרדים בתוך `rules_report` ו־`objects_report`, ותוצאה
כוללת. בתיקיית הפלט נוצרים:

- `rules_report.json` ו־`rules_report.txt`.
- `objects_report.json` ו־`objects_report.txt`.

קובצי הטקסט כוללים כותרות בעברית ופירוט הפערים. הקבצים נכתבים ב־UTF-8.
אין דריסה של דוחות קיימים: יש לבחור תיקיית הרצה חדשה.
נתוני אמת ודוחות הם מידע תשתיתי; יש לשמור אותם בתיקיות `snapshots/` ו־`reports/`
שכבר מוחרגות מ־Git, ולצנזר אותם לפני שיתוף.

לכל דוח תוצאה משלו: `PASS`, `FAIL` או `INDETERMINATE`. התוצאה הכוללת היא
`INDETERMINATE` אם לפחות בדיקה אחת אינה שלמה, אחרת `FAIL` אם יש פער,
ואחרת `PASS`. קודי היציאה הם 2, 1 ו־0 בהתאמה. מידע חלקי יכול להופיע בדוח
אובייקטים עם פערים ידועים, אך התוצאה נשארת `INDETERMINATE`.
מדיניות ריקה מחייבת `--allow-empty` מפורש; כשל API אינו מדיניות ריקה.

`compare_all(source, target)` מפיק את שני הדוחות בלי קבצים.
`save_reports(result, directory)` שומר אותם.
`save_snapshot(rules, path)` שומר את נתוני שני השלבים להרצה חוזרת; הוא אינו
כולל סיסמאות, טוקנים או תגובות API גולמיות ואינו דורס קובץ קיים.

## פורמט נתונים מקומי

קובץ הוא מערך JSON של חוקים מנורמלים. לדוגמה:

```json
[
  {
    "rule_number": "1",
    "source_objects": ["example-host"],
    "destination_objects": ["@any"],
    "destination_services": [["6", 443, 443]],
    "service_objects": ["example-https"],
    "referenced_objects": [
      {"name": "example-host", "kind": "network", "values": ["192.0.2.1/32"]},
      {"name": "example-https", "kind": "service", "values": [["6", 443, 443]]}
    ],
    "issues": [],
    "object_issues": []
  }
]
```

`referenced_objects` כולל את כל האובייקטים המופנים, גם חברים מקוננים.
שדות רשת בקובץ מנורמל חייבים להכיל שמות או `@any` מפורש; מערך ריק אינו
מתורגם אוטומטית ל־Any. מזהי חוקים חוזרים ומפתחות JSON כפולים נדחים,
כדי שלא להסתיר נתונים באמצעות דריסה בזמן טעינה.
`service_objects` כולל שמות שירותים וקבוצות שירות המופנים ישירות מהחוק.
`issues` מציין חוסר בנתונים הרלוונטיים להשוואת חוקים; `object_issues`
מציין איסוף לא שלם של ערכי אובייקטים. רשימת inventory חסרה אינה שקולה
לרשימה ריקה: דוח האובייקטים לא יקבל PASS ללא מידע מלא על ההפניות.
קבצים ישנים עם `object_values` עדיין נטענים, אך אינם מספקים inventory מלא.
שירותים ישנים ללא פרוטוקול, כגון `"443"`, אינם מספקים את ההשוואה שאושרה
ומחזירים `INDETERMINATE`; הכלי אינו מנחש TCP או UDP.
קובצי JSON מנורמלים נחשבים קלט מהימן, ואינם תחליף לפענוח תגובות API גולמיות.

## לקוחות API ומעבדה

מדריך ההרצה והתרחישים נמצא ב־[LAB_GUIDE.md](LAB_GUIDE.md).
בדיקת הגדרות בלבד, ללא בקשות לשרתים וללא הזנת פרטי הזדהות:

```powershell
python lab.py --csm-url https://example.invalid/nbi --fmc-url https://example.invalid --csm-policy example-policy --fmc-policy example-policy --fmc-version 7.4.1 --output-dir reports/lab-001
```

הכתובות והשמות כאן הם דוגמאות בלבד. גרסת FMC היא הצהרה של המפעיל,
ואינה מאומתת אוטומטית. בדיקה זו אינה בודקת זמינות או הרשאות בשרתים.
רק הוספת `--connect` מפעילה חיבור; בשלב הנוכחי אין אישור להריץ אותו.
שמות משתמשים מוזנים בשאלה בזמן ההרצה, וסיסמאות באמצעות `getpass` ללא הדהוד.
אם הסתרת הסיסמה אינה אפשרית, ההרצה נעצרת לפני הזדהות.
אפשר לספק `--csm-ca`, `--fmc-ca`, `--timeout` ו־`--fmc-domain`.
אין אפשרות לבטל אימות TLS במסלול המעבדה.

כל הרצה חיה דורשת תיקייה חדשה בתוך `reports/`. בנוסף לשני הדוחות נשמרים
`csm.snapshot.json`, `fmc.snapshot.json` ו־`run.json` עם זמני UTC, גרסאות
מוצהרות, שלבי כשל ותוצאות ניקוי. אין בו כתובות שרת, שמות משתמשים או סודות.
בכשל ייתכן שרק snapshot אחד נשמר. אין להסיק מכך ששתי המערכות נאספו.
כשל יציאה מהשרת משאיר את תוצאות ההשוואה, אך התוצאה הכוללת של ההרצה
היא `INDETERMINATE`, והכשל מופיע ב־`run.json`.

יצירת לקוח אינה מתחברת. `login` מבצע הזדהות מפורשת בלבד.

- `CSMClient('https://example.invalid/nbi')`: `getPolicy`, `PolicyRules`,
  `policy_rules`, `getGIDByName`, `getPolicyList`, `logout`.
- `FMCClient('https://example.invalid', domain='explicit-domain-uuid')`:
  `policy_uuid_by_name`, `policy_rules`, `close`. ללא domain מפורש, נדרש domain יחיד.
- `compare_policies(csm_client, csm_name, fmc_client, fmc_name)` מקבל לקוחות
  שכבר התחברו, ומחזיר את שני הדוחות. האחריות לסגירת החיבורים היא של הקורא.

TLS מאומת כברירת מחדל. ניתן לספק נתיב CA, `timeout` ו־session מוזרק.
`close` ב־CSM מנסה logout ומנקה את המצב המקומי גם בכשל;
ב־FMC הוא מוחק את הטוקן המקומי וסוגר את חיבור HTTP, בלי לבטל טוקן בשרת.
אין מעקב אחרי redirects. תגובת 429 מטופלת עד חמישה ניסיונות; כשלי HTTP,
הזדהות ותקשורת עוצרים איסוף. פרטי חריגה גולמיים אינם מועתקים לדוחות.
כשל איסוף ברמת המדיניות מציין את השלב ואת קטגוריית הכשל.
דפדוף ב־CSM משתמש ב־endIndex של הדף הקודם כ־startIndex; ב־FMC משתמשים
ב־offset/limit וב־paging.count. נבדקים מזהים חוזרים, עצירה והבדלים בספירות.
מטמון תשובות האובייקטים מוגבל לאיסוף מדיניות אחד; כל חוק מקבל inventory
של כל הפניותיו, גם כאשר נתוני האובייקט כבר במטמון.

אין כלי שיכול להבטיח snapshot עקבי בזמן שמדיניות משתנה בשרת. יש לאסוף
בחלון מעבדה ללא שינויים מקבילים. אין להשתמש בקוד לחיבור לייצור ללא אישור.
אין לשמור סיסמאות בקוד, בקבצים מנוהלים או בארגומנטים; בקורא מורשה יש
להשתמש ב־getpass או בספק סודות מאושר.

הבדיקות המדומות אינן מוכיחות תאימות לגרסת FMC מותקנת. סיום הפרויקט
דורש בדיקה מתועדת מול שרתי CSM ו־FMC במעבדה, לאחר אישור מפורש לחיבור.
יש לבדוק התאמה, פערי חוקים, שינויי אובייקטים, קבוצות מקוננות, דפדוף וכשלים.

מגבלות שנותרו: גרסת FMC לא נמסרה; מדיניות CSM מקומית, חריגות אובייקטים
לפי מכשיר, FQDN ופרוטוקולים שאינם IP-any/TCP/UDP עדיין אינם נתמכים.
אין חידוש טוקן אוטומטי או משא ומתן על גרסת שירות CSM. NAT, ניתוב, מצב פריסה
ופעולת ברירת מחדל אינם בתחום הבדיקה.

## מקורות API

- [CSM 4.25 API specification](https://www.cisco.com/c/dam/en/us/td/docs/security/security_management/cisco_security_manager/security_manager/425/API/CSM-API-Spec-v25.pdf): pagination, network/service objects, port lists and shared policies.
- [FMC 7.4.1 REST objects guide](https://www.cisco.com/c/en/us/td/docs/security/firepower/741/api/REST/secure_firewall_management_center_rest_api_quick_start_guide_741/Objects_In_The_REST_API.html): object and access-rule endpoints, expanded collections and pagination.
- [FMC 7.4.1 authentication guide](https://www.cisco.com/c/en/us/td/docs/security/firepower/741/api/REST/secure_firewall_management_center_rest_api_quick_start_guide_741/Connecting_With_A_Client.html): explicit token generation and token expiration.
