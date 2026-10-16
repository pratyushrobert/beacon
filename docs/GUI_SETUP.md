# Beacon GUI - Setup Instructions

## Prerequisites
- Python 3.10+
- Node.js 18+ and npm
- TShark installed

## Quick Start

### 1. Install Python Dependencies
```bash
# From project repository root
pip install -r requirements.txt
pip install -e .
```

### 2. Install Node.js Dependencies
```bash
cd web
npm install
```

### 3. Start the Backend API
```bash
# In your first terminal (from project root)
python -m uvicorn beacon.api.server:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at http://localhost:8000

### 4. Start the Frontend (in a new terminal)
```bash
# In your second terminal
cd web
npm run dev
```

The web interface will be available at http://localhost:3000

## Usage

1. **Open** http://localhost:3000 in your browser
2. **Upload** a PCAP/PCAPNG file via drag-and-drop
3. **Select** analysis mode (Blue/Red/White)
4. **Click** "Start Analysis"
5. **Explore** the results:
   - Dashboard - Overview with charts
   - Findings - Security detections
   - Hosts - Per-host analysis
   - Conversations - Network flows
   - Timeline - Event chronology
   - Packets - Deep inspection

## Features

### Beautiful Modern UI
- Dark mode support (default)
- Responsive design
- Professional color scheme
- Smooth animations
- Accessible components

### Analysis Modes
- **Blue Mode** - Defensive analysis (scans, beaconing, anomalies)
- **Red Mode** - Offensive analysis (credentials, info leakage)
- **White Mode** - Neutral exploration

### Dashboard
- Traffic statistics
- Protocol distribution pie chart
- Findings by severity bar chart
- Top hosts table
- Recent findings

### Findings
- Severity filtering (Critical/High/Medium/Low/Info)
- Expandable details
- Evidence display
- Recommendations
- Color-coded severity badges

### Hosts
- Complete host inventory
- Internal/External classification
- Traffic statistics
- Protocol breakdown

### Conversations
- Bidirectional flows
- Port information
- Duration tracking
- Traffic volume

## API Endpoints

- `POST /api/upload` - Upload PCAP file
- `POST /api/analyze/{id}` - Start analysis
- `GET /api/analysis/{id}/status` - Check status
- `GET /api/analysis/{id}/results` - Get results
- `GET /api/analysis/{id}/findings` - Get findings (with filters)
- `GET /api/analysis/{id}/hosts` - Get hosts
- `GET /api/analysis/{id}/conversations` - Get conversations
- `DELETE /api/analysis/{id}` - Delete analysis

## Development

### Backend Development
```bash
# Auto-reload on code changes
python -m uvicorn beacon.api.server:app --reload
```

### Frontend Development
```bash
# Vite dev server with hot reload
cd web
npm run dev
```

### Build for Production
```bash
cd web
npm run build
# Output in web/dist/
```

## Technology Stack

### Backend
- FastAPI - Modern Python web framework
- Uvicorn - ASGI server
- Beacon - Analysis engine

### Frontend
- React 18 - UI framework
- Vite - Build tool
- Tailwind CSS - Styling
- Recharts - Charts
- Lucide React - Icons
- Axios - HTTP client
- React Router - Routing
- React Dropzone - File upload

## Troubleshooting

### API won't start
- Check Python dependencies: `pip install -r requirements.txt`
- Verify port 8000 is not in use
- Check TShark is installed: `tshark --version`

### Frontend won't start
- Check Node.js version: `node --version` (should be 18+)
- Delete node_modules and reinstall: `rm -rf node_modules && npm install`
- Verify port 3000 is not in use

### Analysis fails
- Check TShark is in PATH
- Verify PCAP file is valid
- Check API logs for errors

### Charts not displaying
- Ensure data is being returned from API
- Check browser console for errors
- Try refreshing the page

## Next Steps

### Planned Features
- Real-time analysis progress with WebSocket
- Network graph visualization
- Advanced packet explorer
- Interactive timeline
- Report generation (HTML/PDF)
- Search functionality
- Finding correlation
- IOC export

## Notes

- First analysis of a file takes time (depending on size)
- Results are cached - re-analysis is instant
- Cache stored in system temp directory
- Dark mode is default (toggle in sidebar)
- All timestamps shown in local timezone
