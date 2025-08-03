import { Component, signal, computed } from '@angular/core';

@Component({
  selector: 'app-root',
  imports: [],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App {
    protected title = 'jwt.io.old';
    
    protected encodedJwt = signal('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');
    
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

    protected isValidJwt = computed(() => {
        const jwt = this.encodedJwt().trim();
        if (!jwt) return false;
        const parts = jwt.split('.');
        return parts.length === 3 && parts.every(part => part.length > 0);
    });

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
}
