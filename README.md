# AOSEye

AOSEye는 APK 한 개를 입력받아 Android manifest, resources.arsc, DEX 문자열과 native library 목록을 검사하고 HTML(기본) 또는 TXT 보고서를 만드는 Python CLI입니다. APK를 디컴파일한 결과는 별도로 저장하지 않습니다.

## 설치

Python 3.10 이상이 필요합니다.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install -e .
```

## 실행

HTML 보고서가 기본이며 현재 디렉터리에 `<APK이름>_aoseye_report.html`로 저장됩니다.

```powershell
python -m aoseye C:\path\target.apk
python -m aoseye C:\path\target.apk --format txt --output C:\reports\target.txt
python -m aoseye C:\path\target.apk --no-network
```

설치 후에는 `aoseye C:\path\target.apk` 명령도 사용할 수 있습니다. CI에서 취약 판정 시 종료 코드 1이 필요하면 `--fail-on-vulnerable`을 추가합니다. 일반 실행은 취약점이 발견되어도 보고서 생성에 성공하면 종료 코드 0을 반환합니다.

주요 옵션:

- `-f, --format {html,txt}`: 저장 형식(기본 `html`)
- `-o, --output PATH`: 저장 경로
- `--no-network`: Firebase Remote Config 확인 생략
- `--timeout SECONDS`: Firebase 요청 제한 시간(기본 10초)
- `--fail-on-vulnerable`: 취약 판정이 있으면 종료 코드 1

## 검사 항목과 판정 기준

1. **Task Hijacking**: `minSdkVersion <= 29`이고 하나 이상의 Activity가 `launchMode=singleTask`이면 취약으로 판정합니다.
2. **Overlay Fishing 방어**: `android.permission.HIDE_OVERLAY_WINDOWS` 권한 선언이 없으면 요청된 권한 기반 기준에 따라 취약으로 판정합니다.
3. **디버깅 모드**: 유효 `android:debuggable` 값이 `true`이면 취약입니다. 생략 시 Android 기본값 `false`를 적용합니다.
4. **앱 백업**: 유효 `android:allowBackup` 값이 `true`이면 취약입니다. 생략 시 Android 기본값 `true`를 적용합니다.
5. **Firebase Remote Config**: `google_api_key`, `google_app_id`, `gcm_defaultSenderId`를 리소스에서 찾아 client fetch endpoint로 읽기 전용 POST 요청을 보냅니다. HTTP 200이면 응답을 보고서에 싣고 구성 내 민감정보 검토가 필요한 상태로 판정합니다.
6. **보안 솔루션 라이브러리**: APK ZIP 엔트리에서 `libloader.so`(NHN AppGuard), `libdxbase.so`(NSHC)를 검색합니다.
7. **외부 Activity**: 명시적 `exported=true`와 intent-filter로 인한 암묵적 노출을 표시하고 `adb shell am start -n` 명령을 생성합니다.
8. **Deep Link**: `VIEW` action과 `BROWSABLE` category가 있는 intent-filter의 URI 패턴 및 ADB 호출 명령을 생성합니다.
9. **Content Provider**: 요청 범위에 맞춰 명시적으로 `exported=true`인 Provider, authorities와 read/write permission을 표시합니다.
10. **전체 Activity**: Activity와 activity-alias 전체를 보고서 후반에 표시합니다.
11. **민감 문자열 후보**: 기본/현지화 문자열 리소스와 모든 DEX string pool에서 URL, AWS Access Key ID, Cognito pool, Google/Firebase API key, Firebase Database URL, OAuth client ID, private-key marker를 찾습니다.

## 해석 시 주의사항

- 이 도구는 휴리스틱 정적 분석기입니다. 취약 판정은 코드 실행 경로, 서버 측 권한, 런타임 방어를 모두 증명하지 않으므로 수동 검증이 필요합니다.
- Firebase API key와 Remote Config 값은 일반적으로 클라이언트에 배포될 수 있습니다. HTTP 200 자체를 비밀키 유출의 증명으로 보지 말고, 반환된 `entries`에 비밀이나 위험한 동작 제어값이 있는지 확인해야 합니다. 검사는 Remote Config quota를 소량 소비할 수 있습니다.
- Overlay 검사는 요청된 권한 선언만 봅니다. `filterTouchesWhenObscured`, `setHideOverlayWindows`, Compose/커스텀 터치 처리 같은 코드 수준 방어는 별도 검토가 필요합니다.
- Android 12 이상에서는 백업 동작이 제조사 및 `dataExtractionRules`에 따라 달라질 수 있습니다. 보고서는 manifest의 유효 `allowBackup` 값을 우선 표시합니다.
- URL과 클라우드 식별자는 정상 공개 값일 수 있습니다. 민감 문자열 결과는 후보 목록입니다.

## 테스트

```powershell
python -m unittest discover -s tests -v
```
