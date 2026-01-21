class PIIChatbot {
    constructor() {
        this.chatMessages = document.getElementById('chatMessages');
        this.userInput = document.getElementById('userInput');
        this.sendBtn = document.getElementById('sendBtn');
        this.attachBtn = document.getElementById('attachBtn');
        this.fileInput = document.getElementById('fileInput');
        this.btsPanel = document.getElementById('btsPanel');
        this.btsToggle = document.getElementById('btsToggle');
        this.btsContent = document.getElementById('btsContent');
        this.statusIndicator = document.getElementById('statusIndicator');
        this.imageModal = document.getElementById('imageModal');

        this.initializeEventListeners();
    }

    initializeEventListeners() {
        // Send button
        this.sendBtn.addEventListener('click', () => this.sendMessage());

        // Attach button
        this.attachBtn.addEventListener('click', () => {
            console.log('Attach button clicked'); // Debug log
            this.fileInput.click();
        });

        // File input
        this.fileInput.addEventListener('change', (e) => {
            console.log('File selected:', e.target.files[0]); // Debug log
            this.handleFileUpload(e);
        });

        // Enter to send (Shift+Enter for new line)
        this.userInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });

        // Auto-resize textarea
        this.userInput.addEventListener('input', () => {
            this.userInput.style.height = 'auto';
            this.userInput.style.height = this.userInput.scrollHeight + 'px';
        });

        // BTS toggle
        this.btsToggle.addEventListener('click', () => {
            this.btsPanel.classList.toggle('active');
            this.btsToggle.classList.toggle('active');
            const icon = document.getElementById('btsIcon');
            icon.textContent = this.btsPanel.classList.contains('active') ? '✖️' : '👁️';
        });

        // Modal close (only if modal exists)
        if (this.imageModal) {
            const modalClose = document.querySelector('.modal-close');
            if (modalClose) {
                modalClose.addEventListener('click', () => {
                    this.imageModal.classList.remove('active');
                });
            }

            // Close modal on outside click
            this.imageModal.addEventListener('click', (e) => {
                if (e.target === this.imageModal) {
                    this.imageModal.classList.remove('active');
                }
            });
        }
    }

    async sendMessage() {
        const message = this.userInput.value.trim();
        
        if (!message) return;

        // Disable input
        this.setLoading(true);

        // Add user message
        this.addMessage(message, 'user');

        // Clear input
        this.userInput.value = '';
        this.userInput.style.height = 'auto';

        try {
            const response = await fetch('/chat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message })
            });

            const data = await response.json();

            if (data.success) {
                // Add bot response
                this.addMessage(data.llm_response, 'bot');

                // Update BTS panel
                this.updateBTSText(data);
            } else {
                this.addMessage(`Error: ${data.error}`, 'bot', true);
            }
        } catch (error) {
            console.error('Chat error:', error);
            this.addMessage('Sorry, something went wrong. Please try again.', 'bot', true);
        } finally {
            this.setLoading(false);
        }
    }

    async handleFileUpload(event) {
        const file = event.target.files[0];
        if (!file) {
            console.log('No file selected');
            return;
        }

        console.log('Processing file:', file.name, file.type, file.size);

        // Reset file input
        event.target.value = '';

        // Show processing message
        this.addFileProcessingMessage(file.name);
        this.setLoading(true, `Processing ${file.name}...`);

        try {
            const formData = new FormData();
            formData.append('file', file);

            console.log('Uploading file...');

            const response = await fetch('/upload', {
                method: 'POST',
                body: formData
            });

            console.log('Response status:', response.status);

            const data = await response.json();
            console.log('Response data:', data);

            if (data.success) {
                // Remove processing message
                this.removeLastMessage();

                // Add result based on file type
                if (data.file_type === 'image') {
                    this.addImageResult(data);
                } else if (data.file_type === 'pdf') {
                    this.addPDFResult(data);
                } else if (data.file_type === 'spreadsheet') {
                    this.addSpreadsheetResult(data);
                }

                // Update BTS panel
                this.updateBTSFile(data);
            } else {
                this.removeLastMessage();
                this.addMessage(`Error processing file: ${data.error}`, 'bot', true);
            }
        } catch (error) {
            console.error('Upload error:', error);
            this.removeLastMessage();
            this.addMessage('Sorry, file upload failed. Please try again.', 'bot', true);
        } finally {
            this.setLoading(false);
        }
    }

    addFileProcessingMessage(filename) {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message bot-message processing';
        messageDiv.innerHTML = `
            <div class="processing-file">
                <div class="spinner"></div>
                <div>
                    <strong>Processing file...</strong>
                    <p style="margin: 0; font-size: 0.875rem; color: var(--text-secondary);">${this.escapeHtml(filename)}</p>
                </div>
            </div>
        `;
        this.chatMessages.appendChild(messageDiv);
        this.scrollToBottom();
    }

    addImageResult(data) {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message bot-message';
        
        const summary = data.summary;
        
        messageDiv.innerHTML = `
            <div class="message-content">
                <strong>🖼️ Image Redaction Complete</strong>
                <div class="file-message">
                    <div class="file-info">
                        <div class="file-icon">🖼️</div>
                        <div class="file-details">
                            <h4>${this.escapeHtml(data.original_filename)}</h4>
                            <div class="file-meta">
                                ${summary.total_detections} detections • ${summary.total_redactions} redactions
                            </div>
                        </div>
                    </div>
                    
                    <div class="detection-grid">
                        ${Object.entries(summary.by_type).map(([type, count]) => `
                            <div class="detection-card">
                                <div class="detection-type">${type.replace('_', ' ')}</div>
                                <div class="detection-count">${count}</div>
                            </div>
                        `).join('')}
                    </div>

                    ${summary.by_severity && Object.keys(summary.by_severity).length > 0 ? `
                        <div style="margin-top: 1rem;">
                            <strong style="font-size: 0.875rem;">Severity Levels:</strong><br>
                            ${Object.entries(summary.by_severity).map(([severity, count]) => `
                                <span class="severity-badge severity-${severity.toLowerCase()}">${severity}: ${count}</span>
                            `).join(' ')}
                        </div>
                    ` : ''}

                    <div class="file-actions">
                        <button class="btn-view" onclick="chatbot.showImageComparison('${data.original_image}', '${data.redacted_image}')">
                            👁️ Compare Images
                        </button>
                        <button class="btn-download" onclick="window.open('${data.download_url}', '_blank')">
                            ⬇️ Download Redacted
                        </button>
                    </div>
                </div>
            </div>
        `;

        this.chatMessages.appendChild(messageDiv);
        this.scrollToBottom();
    }

    addPDFResult(data) {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message bot-message';
        
        const summary = data.summary;
        
        messageDiv.innerHTML = `
            <div class="message-content">
                <strong>📄 PDF Redaction Complete</strong>
                <div class="file-message">
                    <div class="file-info">
                        <div class="file-icon">📄</div>
                        <div class="file-details">
                            <h4>${this.escapeHtml(data.original_filename)}</h4>
                            <div class="file-meta">
                                ${data.pages} pages • ${summary.total_redacted} entities redacted
                            </div>
                        </div>
                    </div>

                    ${summary.total_redacted > 0 ? `
                        <div style="margin-top: 1rem;">
                            <strong style="font-size: 0.875rem;">Redacted Entities:</strong>
                            <div style="margin-top: 0.5rem;">
                                ${Object.keys(summary.redacted_entities).slice(0, 10).map(entity => 
                                    `<span class="entity-item">${this.escapeHtml(entity)}</span>`
                                ).join('')}
                                ${Object.keys(summary.redacted_entities).length > 10 ? 
                                    `<span style="font-size: 0.875rem; color: var(--text-secondary);">+${Object.keys(summary.redacted_entities).length - 10} more</span>` 
                                    : ''}
                            </div>
                        </div>
                    ` : ''}

                    <div class="file-actions">
                        <button class="btn-download" onclick="window.open('${data.download_url}', '_blank')">
                            ⬇️ Download Redacted PDF
                        </button>
                    </div>
                </div>
            </div>
        `;

        this.chatMessages.appendChild(messageDiv);
        this.scrollToBottom();
    }

    addSpreadsheetResult(data) {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message bot-message';
        
        const summary = data.summary;
        
        messageDiv.innerHTML = `
            <div class="message-content">
                <strong>📊 Spreadsheet Redaction Complete</strong>
                <div class="file-message">
                    <div class="file-info">
                        <div class="file-icon">📊</div>
                        <div class="file-details">
                            <h4>${this.escapeHtml(data.original_filename)}</h4>
                            <div class="file-meta">
                                ${summary.cells_redacted} cells redacted
                            </div>
                        </div>
                    </div>

                    <div class="spreadsheet-stats">
                        ${summary.sheets_processed ? `
                            <div class="stat-box">
                                <div class="label">Sheets</div>
                                <div class="value">${summary.sheets_processed}</div>
                            </div>
                        ` : ''}
                        ${summary.rows ? `
                            <div class="stat-box">
                                <div class="label">Rows</div>
                                <div class="value">${summary.rows}</div>
                            </div>
                        ` : ''}
                        ${summary.columns ? `
                            <div class="stat-box">
                                <div class="label">Columns</div>
                                <div class="value">${summary.columns}</div>
                            </div>
                        ` : ''}
                        <div class="stat-box">
                            <div class="label">Redacted</div>
                            <div class="value">${summary.cells_redacted}</div>
                        </div>
                    </div>

                    <div class="file-actions">
                        <button class="btn-download" onclick="window.open('${data.download_url}', '_blank')">
                            ⬇️ Download Redacted File
                        </button>
                    </div>
                </div>
            </div>
        `;

        this.chatMessages.appendChild(messageDiv);
        this.scrollToBottom();
    }

    showImageComparison(originalSrc, redactedSrc) {
        if (!this.imageModal) {
            console.error('Image modal not found');
            return;
        }
        document.getElementById('originalImage').src = originalSrc;
        document.getElementById('redactedImage').src = redactedSrc;
        this.imageModal.classList.add('active');
    }

    addMessage(text, sender, isError = false) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${sender}-message`;

        const icon = sender === 'user' ? '👤' : '🤖';
        const label = sender === 'user' ? 'You' : 'Assistant';

        messageDiv.innerHTML = `
            <div class="message-content ${isError ? 'error' : ''}">
                <strong>${icon} ${label}</strong>
                <p>${this.escapeHtml(text)}</p>
            </div>
        `;

        this.chatMessages.appendChild(messageDiv);
        this.scrollToBottom();
    }

    removeLastMessage() {
        const messages = this.chatMessages.querySelectorAll('.message');
        if (messages.length > 0) {
            messages[messages.length - 1].remove();
        }
    }

    updateBTSText(data) {
        const { original_message, redacted_message, llm_response_raw, redaction_summary } = data;

        const highlightedOriginal = this.highlightRedactions(
            original_message, 
            redaction_summary.redacted_entities
        );

        const highlightedKept = this.highlightKept(
            original_message,
            redaction_summary.kept_entities
        );

        this.btsContent.innerHTML = `
            <div class="bts-block">
                <h4>📝 Original Message</h4>
                <div class="bts-text">${highlightedOriginal || highlightedKept}</div>
            </div>

            <div class="bts-block">
                <h4>🔒 Redacted Message (Sent to LLM)</h4>
                <div class="bts-text">${this.escapeHtml(redacted_message)}</div>
            </div>

            <div class="bts-block">
                <h4>🤖 LLM Raw Response (Before De-anonymization)</h4>
                <div class="bts-text">${this.escapeHtml(llm_response_raw)}</div>
            </div>

            <div class="redaction-summary">
                <h4>📊 Redaction Summary</h4>
                <div class="summary-stats">
                    <div class="stat-item">
                        <div class="stat-value">${redaction_summary.total_redacted}</div>
                        <div class="stat-label">Redacted</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">${redaction_summary.total_kept}</div>
                        <div class="stat-label">Kept (Public)</div>
                    </div>
                </div>

                ${redaction_summary.total_redacted > 0 ? `
                    <div class="entity-list">
                        <strong style="font-size: 0.875rem;">Redacted Entities:</strong><br>
                        ${Object.entries(redaction_summary.redacted_entities)
                            .map(([original, placeholder]) => 
                                `<span class="entity-item">${this.escapeHtml(original)} → ${this.escapeHtml(placeholder)}</span>`
                            ).join('')}
                    </div>
                ` : ''}

                ${redaction_summary.total_kept > 0 ? `
                    <div class="entity-list">
                        <strong style="font-size: 0.875rem;">Kept Entities (Public Figures):</strong><br>
                        ${redaction_summary.kept_entities
                            .map(entity => `<span class="entity-item kept">${this.escapeHtml(entity)}</span>`)
                            .join('')}
                    </div>
                ` : ''}
            </div>
        `;
    }

    updateBTSFile(data) {
        let content = `
            <div class="bts-block">
                <h4>📁 File Processing Summary</h4>
                <div class="bts-text">
                    <strong>File:</strong> ${this.escapeHtml(data.original_filename)}<br>
                    <strong>Type:</strong> ${data.file_type.toUpperCase()}<br>
                </div>
            </div>
        `;

        if (data.file_type === 'image') {
            const summary = data.summary;
            content += `
                <div class="bts-block">
                    <h4>🔍 Detection Details</h4>
                    <div class="detection-grid">
                        ${Object.entries(summary.by_type).map(([type, count]) => `
                            <div class="detection-card">
                                <div class="detection-type">${type.replace('_', ' ')}</div>
                                <div class="detection-count">${count}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>

                ${data.detections && data.detections.length > 0 ? `
                    <div class="bts-block">
                        <h4>📋 Sample Detections</h4>
                        <div style="font-size: 0.875rem; font-family: monospace;">
                            ${data.detections.slice(0, 5).map((det, i) => `
                                ${i + 1}. <strong>${det.type}</strong> (confidence: ${(det.confidence * 100).toFixed(0)}%)
                            `).join('<br>')}
                        </div>
                    </div>
                ` : ''}

                ${summary.compliance_notes && summary.compliance_notes.length > 0 ? `
                    <div class="compliance-status">
                        <h4>✓ Compliance Notes</h4>
                        <ul class="compliance-list">
                            ${summary.compliance_notes.map(note => `<li>${this.escapeHtml(note)}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
            `;
        } else if (data.file_type === 'pdf') {
            const summary = data.summary;
            content += `
                <div class="redaction-summary">
                    <h4>📊 Redaction Summary</h4>
                    <div class="summary-stats">
                        <div class="stat-item">
                            <div class="stat-value">${data.pages}</div>
                            <div class="stat-label">Pages</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value">${summary.total_redacted}</div>
                            <div class="stat-label">Redacted</div>
                        </div>
                    </div>
                </div>
            `;
        } else if (data.file_type === 'spreadsheet') {
            const summary = data.summary;
            content += `
                <div class="redaction-summary">
                    <h4>📊 Processing Summary</h4>
                    <div class="summary-stats">
                        ${summary.sheets_processed ? `
                            <div class="stat-item">
                                <div class="stat-value">${summary.sheets_processed}</div>
                                <div class="stat-label">Sheets</div>
                            </div>
                        ` : ''}
                        <div class="stat-item">
                            <div class="stat-value">${summary.cells_redacted}</div>
                            <div class="stat-label">Cells Redacted</div>
                        </div>
                    </div>
                </div>
            `;
        }

        this.btsContent.innerHTML = content;
    }

    highlightRedactions(text, redactedEntities) {
        let highlighted = this.escapeHtml(text);
        
        const sortedEntities = Object.keys(redactedEntities).sort((a, b) => b.length - a.length);

        for (const entity of sortedEntities) {
            const escapedEntity = this.escapeHtml(entity);
            const regex = new RegExp(`\\b${this.escapeRegex(escapedEntity)}\\b`, 'gi');
            highlighted = highlighted.replace(
                regex, 
                `<span class="redacted">${escapedEntity}</span>`
            );
        }

        return highlighted;
    }

    highlightKept(text, keptEntities) {
        let highlighted = this.escapeHtml(text);

        for (const entity of keptEntities) {
            const escapedEntity = this.escapeHtml(entity);
            const regex = new RegExp(`\\b${this.escapeRegex(escapedEntity)}\\b`, 'gi');
            highlighted = highlighted.replace(
                regex,
                `<span class="kept">${escapedEntity}</span>`
            );
        }

        return highlighted;
    }

    setLoading(isLoading, message = null) {
        this.sendBtn.disabled = isLoading;
        this.userInput.disabled = isLoading;
        this.attachBtn.disabled = isLoading;
        this.sendBtn.classList.toggle('loading', isLoading);
        
        this.statusIndicator.innerHTML = isLoading 
            ? `<span class="dot"></span> ${message || 'Processing...'}`
            : '<span class="dot"></span> Ready';
    }

    scrollToBottom() {
        this.chatMessages.scrollTop = this.chatMessages.scrollHeight;
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    escapeRegex(string) {
        return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
}

// Initialize chatbot when DOM is ready
let chatbot;
document.addEventListener('DOMContentLoaded', () => {
    chatbot = new PIIChatbot();
    console.log('Chatbot initialized');
});