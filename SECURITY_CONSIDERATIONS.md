# 보안 추가 고려 사항 (Security Considerations)

현재 구현된 **AES-GCM 암호화 + ECDH 키 교환 + HMAC 인증**은 네트워크 구간 및 기본적인 클라이언트 식별 보안을 제공합니다.
하지만 완벽한 서비스 보호(DRM 및 어뷰징 방지)를 위해서는 다음 사항들을 추가로 고려해야 합니다.

## 1. 키 및 Secret 보호 (Key Protection)
소스 코드에 하드코딩된 `CLIENT_SECRET`은 디컴파일 시 노출될 위험이 있습니다.

*   **Mobile (Android/iOS)**:
    *   **Keystore / Keychain**: OS가 제공하는 안전한 저장소에 키를 보관합니다.
    *   **NDK / C++ Layer**: 중요 로직을 네이티브 라이브러(.so)로 옮기고 난독화(Obfuscation)를 적용하여 분석 난이도를 높입니다.
    *   **WhiteBox Cryptography**: 키를 메모리에 노출시키지 않고 암호 연산을 수행하는 상용 솔루션을 도입합니다.
*   **Web**:
    *   브라우저 환경 특성상 완벽한 키 은닉은 불가능합니다.
    *   **Obfuscation**: JS 난독화 도구(UglifyJS 등)를 사용하여 코드 가독성을 떨어뜨립니다.
    *   **User Session Binding**: 반드시 로그인 후 발급된 세션 토큰과 연동하여, 키 교환 요청을 특정 사용자에게 귀속시킵니다.

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
