import { Component, signal, computed, effect } from '@angular/core';

@Component({
  selector: 'app-root',
  imports: [],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App {
    protected title = 'jwt.io.old';
    
    protected encodedJwt = signal('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');
    protected secret = signal('your-256-bit-secret');
    protected isSecretBase64 = signal(false);
    protected signatureVerificationResult = signal<{isValid: boolean | null, message: string}>({ isValid: null, message: 'Enter secret to verify' });

    constructor() {
        // Effect para verificar la firma cuando cambie el token o el secret
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

    // Método para verificar la firma de forma asíncrona
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
            // Decodificar el header para verificar el algoritmo
            const header = JSON.parse(this.base64UrlDecode(parts[0]));
            
            if (header.alg !== 'HS256') {
                this.signatureVerificationResult.set({ isValid: false, message: `Algorithm ${header.alg} not supported` });
                return;
            }

            // Crear los datos a verificar (header.payload)
            const dataToVerify = `${parts[0]}.${parts[1]}`;
            const signature = parts[2];

            // Verificar la firma
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

    private base64Decode(str: string): string {
        try {
            return atob(str);
        } catch (error) {
            throw new Error('Invalid base64 string');
        }
    }

    // Función para convertir string a ArrayBuffer
    private stringToArrayBuffer(str: string): ArrayBuffer {
        const encoder = new TextEncoder();
        return encoder.encode(str);
    }

    // Función para convertir base64 a ArrayBuffer
    private base64ToArrayBuffer(base64: string): ArrayBuffer {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    // Función para verificar firma HMAC usando Web Crypto API
    private async verifyHmacSignature(data: string, signature: string, secret: string): Promise<boolean> {
        try {
            // Obtener el secret como ArrayBuffer
            const secretBuffer = this.isSecretBase64() 
                ? this.base64ToArrayBuffer(secret)
                : this.stringToArrayBuffer(secret);

            // Crear la clave HMAC
            const key = await crypto.subtle.importKey(
                'raw',
                secretBuffer,
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['verify']
            );

            // Convertir la firma de base64url a ArrayBuffer
            const signatureBuffer = this.base64ToArrayBuffer(
                signature.replace(/-/g, '+').replace(/_/g, '/').padEnd(
                    signature.length + (4 - signature.length % 4) % 4, '='
                )
            );

            // Verificar la firma
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
        try {
            const target = event.target as HTMLTextAreaElement;
            const newPayloadJson = target.value;
            const payloadObj = JSON.parse(newPayloadJson);
            const parts = this.encodedJwt().split('.');
            if (parts.length === 3) {
                const headerPart = parts[0];
                const newPayloadPart = this.base64UrlEncode(JSON.stringify(payloadObj));
                const signaturePart = parts[2];
                const newJwt = `${headerPart}.${newPayloadPart}.${signaturePart}`;
                this.encodedJwt.set(newJwt);
            }
        } catch (error) {
            console.warn('Invalid JSON in payload');
        }
    }

    protected onJwtInput(event: Event): void {
        const target = event.target as HTMLTextAreaElement;
        this.encodedJwt.set(target.value.trim());
    }

    protected onSecretInput(event: Event): void {
        const target = event.target as HTMLInputElement;
        this.secret.set(target.value);
    }

    protected onSecretBase64Change(event: Event): void {
        const target = event.target as HTMLInputElement;
        this.isSecretBase64.set(target.checked);
    }
}
