# 보안 추가 고려 사항 (Security Considerations)

## 0. 암호화 컴포넌트 역할 및 목적 (Cryptographic Component Roles)
본 프로젝트에서 사용된 각 암호화 기술의 도입 목적과 방어하는 보안 위협은 다음과 같습니다.

### 1) ECDH (Elliptic Curve Diffie-Hellman)
*   **목적**: **안전한 키 교환 (Key Exchange)**.
*   **역할**: 클라이언트와 서버가 서로 비밀 키를 전송하지 않고도, 수학적으로 동일한 비밀 키(Shared Secret)를 생성하게 합니다.
*   **방어 위협**: **도청 (Eavesdropping/Sniffing)**. 해커가 네트워크 패킷을 모두 캡처하더라도, 공유된 비밀 키를 유추할 수 없습니다.

### 2) HMAC-SHA256 (Hash-based Message Authentication Code)
*   **목적**: **데이터 무결성 및 인증 (Integrity & Authentication)**.
*   **역할**: 메시지가 변조되지 않았음(무결성)과, 올바른 키를 가진 송신자가 보냈음(인증)을 검증합니다.
*   **방어 위협**: **중간자 공격 (MITM) 및 데이터 변조**. 공격자가 패킷을 가로채 내용을 바꾸거나, 가짜 클라이언트 흉내를 내는 것을 방지합니다.

### 3) AES-256-GCM (Advanced Encryption Standard - Galois/Counter Mode)
*   **목적**: **데이터 기밀성 (Confidentiality)**.
*   **역할**: 실제 소설 내용(Content)을 암호화하여 인가된 사용자(키를 가진 자)만 읽을 수 있게 합니다.
*   **방어 위협**: **정보 유출**. DB가 털리거나 전송 구간이 노출되어도 원본 내용을 알 수 없습니다.

---

## 1. 키 및 Secret 보호 (Key Protection)
소스 코드에 하드코딩된 `CLIENT_SECRET`은 디컴파일 시 노출될 위험이 있습니다.

*   **Mobile (Android/iOS)**:
    *   **Keystore / Keychain**: OS가 제공하는 안전한 저장소에 키를 보관합니다.
    *   **NDK / C++ Layer**: 중요 로직을 네이티브 라이브러(.so)로 옮기고 난독화(Obfuscation)를 적용하여 분석 난이도를 높입니다.
    *   **WhiteBox Cryptography**: 키를 메모리에 노출시키지 않고 암호 연산을 수행하는 상용 솔루션을 도입합니다.
*   **Web (JavaScript)**:
    *   브라우저 개발자 도구의 "소스 보기"만으로도 키가 쉽게 노출됩니다.
    *   난독화(UglifyJS 등)를 적용해도 문자열 자체는 그대로 포착되기 쉽습니다.
*   **Web (WebAssembly)**:
    *   **장점**: 코드가 바이너리(.wasm)로 컴파일되므로 사람이 바로 읽을 수 없습니다. 분석하려면 역어셈블리(Disassembly) 과정이 필요하여 난이도가 대폭 상승합니다.
    *   **한계**: 하지만 `strings` 명령어나 메모리 덤프를 통해 문자열 상수를 찾아낼 수는 있습니다. 즉, **보안성(Security)** 보다는 **난독화(Obscurity)** 효과가 뛰어난 것입니다.
    *   **User Session Binding**: (공통) 반드시 로그인 후 발급된 세션 토큰과 연동하여, 키 교환 요청을 특정 사용자에게 귀속시킵니다.

## 2. 앱 무결성 검증 (App Attestation)
해커가 앱을 변조(Modding)하여 로직을 우회하거나, 매크로 봇을 사용하는 것을 방지합니다.

*   **Android**: **Google Play Integrity API** (구: SafetyNet)
    *   구글 서버가 앱의 서명, 기기 상태(루팅 여부)를 검증하고 토큰을 발급합니다.
*   **iOS**: **DeviceCheck / App Attest**
    *   애플 서버가 앱의 정품 여부와 기기 무결성을 보증합니다.

### 성능 영향 (Performance Impact)
앱 무결성 검증은 **외부 서버(Google/Apple)와의 통신**을 필요로 하므로, **수백 ms ~ 수 초(1~2초)** 의 지연이 발생할 수 있습니다.
*   **해결책**:
    *   모든 API 요청마다 검증하지 않고, **앱 실행 시 최초 1회** 또는 **중요한 액션(결제, 로그인)** 시에만 검증 토큰을 갱신합니다.
    *   검증된 토큰은 일정 시간(예: 30분) 동안 캐시하여 재사용합니다.
    *   백그라운드 스레드에서 주기적으로 토큰을 갱신합니다.

## 3. 화면 캡처 방지 (Prevent Screen Capture)
복호화된 소설 내용이 화면에 표시될 때, 이를 캡처하거나 녹화하는 것을 막습니다.

*   **Android**: `WindowManager.LayoutParams.FLAG_SECURE` 설정.
    *   스크린샷 시 검은 화면으로 캡처됩니다.
*   **iOS**: `UIScreen.capturedDidChangeNotification` 감지.
    *   녹화 감지 시 콘텐츠를 가리는 뷰(Blind View)를 띄웁니다.
*   **Web**: OS 레벨의 캡처 방지는 불가능합니다. (EME DRM을 사용하더라도 캡처 보드 등 하드웨어 캡처는 막기 힘듦)

## 4. 코드 난독화 (Code Obfuscation)
*   **Android**: **R8 / ProGuard**를 적용하여 불필요한 메타데이터 제거 및 클래스/메서드 이름을 난수화합니다.
*   **iOS**: **SwiftShield** 등 난독화 도구를 사용하거나, 중요 로직(Key Exchange 등)을 C/C++로 작성하여 LLVM IR 단계에서 난독화합니다.

## 5. 성능 비교 분석 (Performance Analysis)

### AES-GCM 단독 (기존 방식)
*   **연산 비용**: 매우 낮음 (하드웨어 가속 지원).
*   **지연 시간 (Latency)**: < 1ms (서버 처리 시간).
*   **보안성**: **낮음**. 대칭키(Shared Secret)를 사전에 안전하게 공유해야 하는 근본적인 문제가 있음. 키 유출 시 모든 통신이 노출됨.

### ECDH + HMAC + AES-GCM (현재 방식)
*   **연산 비용**:
    *   **ECDH Key Pair 생성**: ~1-3ms (CPU 의존).
    *   **공유 비밀 계산**: ~1-3ms.
    *   **HMAC 서명/검증**: < 0.1ms (무시 가능).
*   **지연 시간 (Latency)**: 요청당 약 **5~10ms** 증가. (네트워크 지연 제외)
    *   소설 앱의 "다음 챕터 로딩" 시나리오에서는 사용자가 체감하기 힘든 수준입니다.
*   **보안성**: **매우 높음**.
    *   **Forward Secrecy (전방 향성)**: 매 세션마다 새로운 키를 사용하므로, 나중에 서버 키가 유출되어도 과거의 통신 내용을 복호화할 수 없습니다.

## 6. HKDF 파라미터 (Salt & Info) 보안
코드에 포함된 `HKDF_SALT` ("novel-api-salt")와 `HKDF_INFO` ("aes-gcm-key")는 **비밀(Secret)이 아닌 공개 컨텍스트 정보**입니다.
*   **Salt**: 유도되는 키의 엔트로피를 강화하는 무작위/고정 값입니다. 노출되어도 원본 IK(Input Keying Material)를 모르면 키를 유추할 수 없습니다.
*   **Info**: 파생되는 키의 용도를 구분하는 식별자입니다 (Context Binding). 예: "aes-key", "hmac-key" 등.
*   **결론**: 이 값들은 프로토콜의 일부로서 공개되어도 안전합니다. 중요한 것은 **ECDH Private Key**와 **HMAC CLIENT_SECRET**입니다.

### 결론
보안 강화를 위해 약 10ms 내외의 연산 비용이 추가되었으나, 이는 **텍스트 콘텐츠 서비스에서 무시할 수 있는 수준**입니다. 대규모 트래픽 발생 시 서버 CPU 부하가 증가할 수 있으므로, 필요 시 **세션 재사용 (Session Resumption)** 전략을 도입하여 ECDH 연산 횟수를 줄일 수 있습니다.

## 7. 보안성 비교 (Security Comparison: AES Only vs ECDH+AES)

| 비교 항목 | 1. AES-GCM 단독 사용 (Legacy) | 2. ECDH + HMAC + AES-GCM (Current) |
| :--- | :--- | :--- |
| **키 관리 (Key Mgmt)** | **Static (고정)**. 클라이언트와 서버가 동일한 키를 영구적으로 공유해야 함. | **Ephemeral (일회용)**. 매 요청마다 새로운 세션 키를 생성하고 버림. |
| **전방 향성 (Forward Secrecy)** | **없음 (X)**. 키가 탈취되면 과거/미래의 모든 암호문이 복호화됨. | **있음 (O)**. 서버의 장기 비밀키가 털려도, 과거의 세션 키는 복구할 수 없음. |
| **탈취 영향 (Compromise)** | **치명적 (Catastrophic)**. 앱 배포 후 키 변경이 불가능에 가까움 (앱 업데이트 필요). | **제한적 (Limited)**. 탈취된 세션 키는 해당 1회 통신에만 유효함. |
| **Replay 공격 방어** | 별도 구현 필요 (Timestamp/Nonce 관리). | **기본 내장**. HMAC 서명에 Timestamp가 포함되어 있어 자동 방어됨. |
| **주요 위협** | 키 하드코딩 추출, 패킷 도청 후 복호화. | 실시간 MITM (어렵지만 가능), 클라이언트 로직 변조. |

### 최종 결론
**AES-GCM 단독 사용**은 "자물쇠를 잠그고 열쇠를 문 앞에 숨겨두는 것"과 같습니다 (Reverse Engineering으로 키 추출 가능).
반면, **ECDH 방식**은 "매번 새로운 금고를 만들고 열쇠를 안에서 공유한 뒤 파기하는 것"과 같아, 훨씬 안전합니다.
