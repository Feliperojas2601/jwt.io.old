import { Component, signal, computed, effect } from '@angular/core';

@Component({
  selector: 'app-root',
  imports: [],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App {
    protected title = 'jwt.io.old';
    
    protected Object = Object;
    
    protected encodedJwt = signal('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');
    protected secret = signal('your-256-bit-secret');
    protected isSecretBase64 = signal(false);
    protected signatureVerificationResult = signal<{isValid: boolean | null, message: string}>({ isValid: null, message: 'Enter secret to verify' });

    constructor() {
        effect(() => {
            const token = this.encodedJwt();
            const secret = this.secret();
            this.verifySignatureAsync(token, secret);
        });
    }
    
    private base64UrlDecode(str: string): string {
        try {
            str = str.replace(/-/g, '+').replace(/_/g, '/');
            while (str.length % 4) {
                str += '=';
            }
            return atob(str);
        } catch (error) {
            throw new Error('Invalid base64 string');
        }
    }
    
    protected headerJson = computed(() => {
        try {
            const parts = this.encodedJwt().split('.');
            if (parts.length >= 1 && parts[0]) {
                const decodedHeader = this.base64UrlDecode(parts[0]);
                const header = JSON.parse(decodedHeader);
                return JSON.stringify(header, null, 2);
            }
            return '{\n  "alg": "HS256",\n  "typ": "JWT"\n}';
        } catch (error) {
            return '{\n  "alg": "HS256",\n  "typ": "JWT"\n}';
        }
    });

    protected payloadJson = computed(() => {
        try {
            const parts = this.encodedJwt().split('.');
            if (parts.length >= 2 && parts[1]) {
                const decodedPayload = this.base64UrlDecode(parts[1]);
                const payload = JSON.parse(decodedPayload);
                return JSON.stringify(payload, null, 2);
            }
            return '{\n  "sub": "1234567890",\n  "name": "John Doe",\n  "iat": 1516239022\n}';
        } catch (error) {
            return '{\n  "sub": "1234567890",\n  "name": "John Doe",\n  "iat": 1516239022\n}';
        }
    });

    protected payloadWithDates = computed(() => {
        try {
            const parts = this.encodedJwt().split('.');
            if (parts.length >= 2 && parts[1]) {
                const decodedPayload = this.base64UrlDecode(parts[1]);
                const payload = JSON.parse(decodedPayload);
                const dateInfo: { [key: string]: { timestamp: number, date: string, lineNumber: number } } = {};
                const dateFields = ['iat', 'exp', 'nbf', 'auth_time'];
                const jsonString = JSON.stringify(payload, null, 2);
                const lines = jsonString.split('\n');
                dateFields.forEach(field => {
                    if (payload[field] && typeof payload[field] === 'number') {
                        const timestamp = payload[field];
                        const date = new Date(timestamp * 1000);
                        const lineNumber = lines.findIndex(line => line.includes(`"${field}"`));
                        dateInfo[field] = {
                            timestamp,
                            date: date.toLocaleString('en-US', {
                                year: 'numeric',
                                month: 'long',
                                day: 'numeric',
                                hour: '2-digit',
                                minute: '2-digit',
                                second: '2-digit',
                                timeZoneName: 'short'
                            }),
                            lineNumber
                        };
                    }
                });
                
                return { payload, dateInfo };
            }
            return { 
                payload: { sub: "1234567890", name: "John Doe", iat: 1516239022 }, 
                dateInfo: {
                    iat: {
                        timestamp: 1516239022,
                        date: new Date(1516239022 * 1000).toLocaleString('en-US', {
                            year: 'numeric',
                            month: 'long',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                            second: '2-digit',
                            timeZoneName: 'short'
                        }),
                        lineNumber: 2
                    }
                }
            };
        } catch (error) {
            return { 
                payload: { sub: "1234567890", name: "John Doe", iat: 1516239022 }, 
                dateInfo: {
                    iat: {
                        timestamp: 1516239022,
                        date: new Date(1516239022 * 1000).toLocaleString('en-US', {
                            year: 'numeric',
                            month: 'long',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                            second: '2-digit',
                            timeZoneName: 'short'
                        }),
                        lineNumber: 2
                    }
                }
            };
        }
    });

    protected formatJwtDate(timestamp: number): string {
        const date = new Date(timestamp * 1000);
        const now = new Date();
        const diffMs = date.getTime() - now.getTime();
        const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
        let relativeTime = '';
        if (diffDays > 0) {
            relativeTime = `(in ${diffDays} days)`;
        } else if (diffDays < 0) {
            relativeTime = `(${Math.abs(diffDays)} days ago)`;
        } else {
            relativeTime = '(today)';
        }
        return `${date.toLocaleString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            timeZoneName: 'short'
        })} ${relativeTime}`;
    }

    protected getDateFieldDescription(field: string): string {
        const descriptions: { [key: string]: string } = {
            'iat': 'Issued At - When the token was created',
            'exp': 'Expiration - When the token expires',
            'nbf': 'Not Before - Token is not valid before this time',
            'auth_time': 'Authentication Time - When authentication occurred'
        };
        return descriptions[field] || 'Date field';
    }
    private async verifySignatureAsync(token: string, secret: string): Promise<void> {
        if (!token || !secret) {
            this.signatureVerificationResult.set({ isValid: null, message: 'Token or secret missing' });
            return;
        }
        const parts = token.split('.');
        if (parts.length !== 3) {
            this.signatureVerificationResult.set({ isValid: false, message: 'Invalid token format' });
            return;
        }
        try {
            const header = JSON.parse(this.base64UrlDecode(parts[0]));
            if (header.alg !== 'HS256') {
                this.signatureVerificationResult.set({ isValid: false, message: `Algorithm ${header.alg} not supported` });
                return;
            }
            const dataToVerify = `${parts[0]}.${parts[1]}`;
            const signature = parts[2];
            const isValid = await this.verifyHmacSignature(dataToVerify, signature, secret);
            if (isValid) {
                this.signatureVerificationResult.set({ isValid: true, message: 'Signature verified' });
            } else {
                this.signatureVerificationResult.set({ isValid: false, message: 'Invalid signature' });
            }
        } catch (error) {
            this.signatureVerificationResult.set({ isValid: false, message: 'Verification failed' });
        }
    }

    protected signatureStatus = computed(() => {
        return this.signatureVerificationResult();
    });

    protected isValidJwt = computed(() => {
        const jwt = this.encodedJwt().trim();
        if (!jwt) return false;
        const parts = jwt.split('.');
        return parts.length === 3 && parts.every(part => part.length > 0);
    });

    private stringToArrayBuffer(str: string): ArrayBuffer {
        const encoder = new TextEncoder();
        return encoder.encode(str);
    }

    private base64ToArrayBuffer(base64: string): ArrayBuffer {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    private async generateHmacSignature(data: string, secret: string): Promise<string> {
        try {
            const secretBuffer = this.isSecretBase64() 
                ? this.base64ToArrayBuffer(secret)
                : this.stringToArrayBuffer(secret);
            const key = await crypto.subtle.importKey(
                'raw',
                secretBuffer,
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['sign']
            );
            const signature = await crypto.subtle.sign(
                'HMAC',
                key,
                this.stringToArrayBuffer(data)
            );
            const signatureArray = new Uint8Array(signature);
            let binaryString = '';
            for (let i = 0; i < signatureArray.byteLength; i++) {
                binaryString += String.fromCharCode(signatureArray[i]);
            }
            return btoa(binaryString)
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=/g, '');
        } catch (error) {
            throw new Error('Failed to generate signature');
        }
    }

    private async verifyHmacSignature(data: string, signature: string, secret: string): Promise<boolean> {
        try {
            const secretBuffer = this.isSecretBase64() 
                ? this.base64ToArrayBuffer(secret)
                : this.stringToArrayBuffer(secret);
            const key = await crypto.subtle.importKey(
                'raw',
                secretBuffer,
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['verify']
            );
            const signatureBuffer = this.base64ToArrayBuffer(
                signature.replace(/-/g, '+').replace(/_/g, '/').padEnd(
                    signature.length + (4 - signature.length % 4) % 4, '='
                )
            );
            const isValid = await crypto.subtle.verify(
                'HMAC',
                key,
                signatureBuffer,
                this.stringToArrayBuffer(data)
            );
            return isValid;
        } catch (error) {
            return false;
        }
    }

    private base64UrlEncode(str: string): string {
        return btoa(str)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    protected onPayloadInput(event: Event): void {
        const target = event.target as HTMLTextAreaElement;
        const newPayloadJson = target.value;
        
        try {
            const payloadObj = JSON.parse(newPayloadJson);
            const parts = this.encodedJwt().split('.');
            if (parts.length === 3) {
                const headerPart = parts[0];
                const newPayloadPart = this.base64UrlEncode(JSON.stringify(payloadObj));
                const secret = this.secret().trim();
                if (secret) {
                    const dataToSign = `${headerPart}.${newPayloadPart}`;
                    this.generateHmacSignature(dataToSign, secret)
                        .then(newSignature => {
                            const newJwt = `${headerPart}.${newPayloadPart}.${newSignature}`;
                            this.encodedJwt.set(newJwt);
                        })
                        .catch(error => {
                            console.warn('Failed to sign token:', error);
                            const newJwt = `${headerPart}.${newPayloadPart}.${parts[2]}`;
                            this.encodedJwt.set(newJwt);
                        });
                } else {
                    const newJwt = `${headerPart}.${newPayloadPart}.${parts[2]}`;
                    this.encodedJwt.set(newJwt);
                }
            }
        } catch (error) {
            console.warn('Invalid JSON in payload');
        }
    }

    protected onHeaderInput(event: Event): void {
        const target = event.target as HTMLTextAreaElement;
        const newHeaderJson = target.value;
        
        try {
            const headerObj = JSON.parse(newHeaderJson);
            const parts = this.encodedJwt().split('.');
            if (parts.length === 3) {
                const newHeaderPart = this.base64UrlEncode(JSON.stringify(headerObj));
                const payloadPart = parts[1];
                const secret = this.secret().trim();
                if (secret) {
                    const dataToSign = `${newHeaderPart}.${payloadPart}`;
                    this.generateHmacSignature(dataToSign, secret)
                        .then(newSignature => {
                            const newJwt = `${newHeaderPart}.${payloadPart}.${newSignature}`;
                            this.encodedJwt.set(newJwt);
                        })
                        .catch(error => {
                            console.warn('Failed to sign token:', error);
                            const newJwt = `${newHeaderPart}.${payloadPart}.${parts[2]}`;
                            this.encodedJwt.set(newJwt);
                        });
                } else {
                    const newJwt = `${newHeaderPart}.${payloadPart}.${parts[2]}`;
                    this.encodedJwt.set(newJwt);
                }
            }
        } catch (error) {
            console.warn('Invalid JSON in header');
        }
    }

    protected onJwtInput(event: Event): void {
        const target = event.target as HTMLTextAreaElement;
        this.encodedJwt.set(target.value.trim());
    }

    protected onSecretInput(event: Event): void {
        const target = event.target as HTMLInputElement;
        const newSecret = target.value;
        this.secret.set(newSecret);
        if (newSecret.trim() && this.isValidJwt()) {
            this.resignToken();
        }
    }

    private resignToken(): void {
        const parts = this.encodedJwt().split('.');
        if (parts.length === 3) {
            const secret = this.secret().trim();
            if (secret) {
                const dataToSign = `${parts[0]}.${parts[1]}`;
                this.generateHmacSignature(dataToSign, secret)
                    .then(newSignature => {
                        const newJwt = `${parts[0]}.${parts[1]}.${newSignature}`;
                        this.encodedJwt.set(newJwt);
                    })
                    .catch(error => {
                        console.warn('Failed to re-sign token:', error);
                    });
            }
        }
    }

    protected onSecretBase64Change(event: Event): void {
        const target = event.target as HTMLInputElement;
        this.isSecretBase64.set(target.checked);
        if (this.secret().trim() && this.isValidJwt()) {
            this.resignToken();
        }
    }
}
