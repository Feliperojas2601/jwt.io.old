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
    
    protected headerJson = computed(() => {
        try {
            const parts = this.encodedJwt().split('.');
            if (parts.length >= 1) {
                const header = JSON.parse(atob(parts[0]));
                return JSON.stringify(header, null, 2);
            }
            return '{\n  "alg": "HS256",\n  "typ": "JWT"\n}';
        } catch {
            return '{\n  "alg": "HS256",\n  "typ": "JWT"\n}';
        }
    });

    protected payloadJson = computed(() => {
            try {
            const parts = this.encodedJwt().split('.');
            if (parts.length >= 2) {
                const payload = JSON.parse(atob(parts[1]));
                return JSON.stringify(payload, null, 2);
            }
            return '{\n  "sub": "1234567890",\n  "name": "John Doe",\n  "iat": 1516239022\n}';
        } catch {
            return '{\n  "sub": "1234567890",\n  "name": "John Doe",\n  "iat": 1516239022\n}';
        }
    });

    protected onJwtInput(event: Event): void {
        const target = event.target as HTMLTextAreaElement;
        this.encodedJwt.set(target.value);
    }
}
