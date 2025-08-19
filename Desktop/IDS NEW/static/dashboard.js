// SecureWatch IDS Advanced Dashboard JavaScript
// import io from "socket.io-client"
// import Plotly from "plotly.js"

class AdvancedIDSDashboard {
  constructor() {
    this.socket = io('http://localhost:5000');
    this.monitoring = false
    this.events = []
    this.alerts = []
    this.threatIntelligence = {}
    this.autoRefresh = false
    this.eventFilters = {
      search: "",
      threatLevel: "",
      protocol: "",
    }

    // Chart instances
    this.charts = {}

    // Network topology
    this.networkTopology = null

    // Statistics tracking
    this.previousStats = {}

    this.initializeEventListeners()
    this.initializeSocketEvents()
    this.initializeTabs()
    this.initializeCharts()
    this.loadInitialData()
    this.startPeriodicUpdates()
  }

  initializeEventListeners() {
    // Monitoring controls
    document.getElementById("toggle-monitoring").addEventListener("click", () => {
      this.toggleMonitoring()
    })

    document.getElementById("emergency-stop").addEventListener("click", () => {
      this.emergencyStop()
    })

    // Tab switching
    document.querySelectorAll(".tab-button").forEach((button) => {
      button.addEventListener("click", (e) => {
        this.switchTab(e.target.dataset.tab)
      })
    })

    // Event filtering
    document.getElementById("event-search").addEventListener("input", (e) => {
      this.eventFilters.search = e.target.value.toLowerCase()
      this.filterEvents()
    })

    document.getElementById("threat-filter").addEventListener("change", (e) => {
      this.eventFilters.threatLevel = e.target.value
      this.filterEvents()
    })

    // Auto-refresh toggle
    document.getElementById("auto-refresh-toggle").addEventListener("click", () => {
      this.toggleAutoRefresh()
    })

    // Topology controls
    document.getElementById("topology-refresh").addEventListener("click", () => {
      this.refreshNetworkTopology()
    })

    document.getElementById("topology-zoom-reset").addEventListener("click", () => {
      this.resetTopologyZoom()
    })
  }

  initializeSocketEvents() {
    this.socket.on("connect", () => {
      console.log("Connected to IDS server")
      this.updateConnectionStatus(true)
    })

    this.socket.on("disconnect", () => {
      console.log("Disconnected from IDS server")
      this.updateConnectionStatus(false)
    })

    this.socket.on("new_event", (eventData) => {
      console.log("[SOCKET.IO] Received new_event:", eventData)
      this.addNewEvent(eventData)
      this.updateThreatIntelligence(eventData)
    })

    this.socket.on("new_alert", (alertData) => {
      console.log("[SOCKET.IO] Received new_alert:", alertData)
      this.addNewAlert(alertData)
      this.showNotificationToast(alertData)
    })

    this.socket.on("stats_update", (statsData) => {
      this.updateStats(statsData)
    })

    this.socket.on("status", (statusData) => {
      this.updateMonitoringStatus(statusData.monitoring)
    })

    this.socket.on("threat_intelligence_update", (intelData) => {
      this.updateThreatIntelligenceDisplay(intelData)
    })

    this.socket.on("network_topology_update", (topologyData) => {
      this.updateNetworkTopology(topologyData)
    })
  }

  initializeTabs() {
    // Tab functionality is handled by event listeners
  }

  initializeCharts() {
    // Initialize empty charts
    this.charts.protocol = null
    this.charts.timeline = null
    this.charts.heatmap = null
  }

  async loadInitialData() {
    try {
      // Load stats
      const statsResponse = await fetch("/api/stats")
      const stats = await statsResponse.json()
      this.updateStats(stats)

      // Load events
      const eventsResponse = await fetch("/api/events?limit=100")
      const events = await eventsResponse.json()
      this.events = events
      this.renderEvents()
      // Update stats again so unique IPs is correct
      if (this.previousStats) {
        this.updateStats(this.previousStats)
      }

      // Load alerts
      const alertsResponse = await fetch("/api/alerts?limit=50")
      const alerts = await alertsResponse.json()
      this.alerts = alerts
      this.renderAlerts()

      // Check monitoring status
      const statusResponse = await fetch("/api/monitoring/status")
      const status = await statusResponse.json()
      this.updateMonitoringStatus(status.monitoring)

      // Load threat intelligence
      await this.loadThreatIntelligence()
    } catch (error) {
      console.error("Error loading initial data:", error)
      this.showNotificationToast({
        title: "Connection Error",
        description: "Failed to load initial data",
        severity: "HIGH",
      })
    }
  }

  startPeriodicUpdates() {
    // Update charts every 30 seconds
    setInterval(() => {
      if (this.autoRefresh) {
        this.updateAnalyticsCharts()
      }
    }, 30000)

    // Update threat intelligence every 60 seconds
    setInterval(() => {
      this.loadThreatIntelligence()
    }, 60000)
  }

  async toggleMonitoring() {
    try {
      const endpoint = this.monitoring ? "/api/monitoring/stop" : "/api/monitoring/start"
      const response = await fetch(endpoint, { method: "POST" })
      const result = await response.json()

      this.updateMonitoringStatus(result.monitoring)

      if (result.monitoring) {
        this.showNotificationToast({
          title: "Monitoring Started",
          description: "Network monitoring is now active",
          severity: "LOW",
        })
      }
    } catch (error) {
      console.error("Error toggling monitoring:", error)
    }
  }

  async emergencyStop() {
    try {
      await fetch("/api/monitoring/stop", { method: "POST" })
      this.updateMonitoringStatus(false)
      this.showAlertBanner("Emergency stop activated - All monitoring halted")
    } catch (error) {
      console.error("Error in emergency stop:", error)
    }
  }

  updateConnectionStatus(connected) {
    const statusElement = document.getElementById("connection-status")
    if (connected) {
      statusElement.className = "connection-status connected"
      statusElement.innerHTML = "✓ Connected"
    } else {
      statusElement.className = "connection-status disconnected"
      statusElement.innerHTML = '<span class="loading-spinner"></span> Reconnecting...'
    }
  }

  updateMonitoringStatus(isMonitoring) {
    this.monitoring = isMonitoring
    const indicator = document.getElementById("status-indicator")
    const statusText = document.getElementById("status-text")
    const toggleButton = document.getElementById("toggle-monitoring")
    const emergencyButton = document.getElementById("emergency-stop")

    if (isMonitoring) {
      indicator.classList.add("active")
      statusText.textContent = "Monitoring Active"
      toggleButton.textContent = "Stop Monitoring"
      toggleButton.className = "btn btn-secondary"
      emergencyButton.classList.remove("hidden")
    } else {
      indicator.classList.remove("active")
      statusText.textContent = "Monitoring Stopped"
      toggleButton.textContent = "Start Monitoring"
      toggleButton.className = "btn btn-primary"
      emergencyButton.classList.add("hidden")
    }
  }

  updateStats(stats) {
    // Update basic stats
  document.getElementById("total-events").textContent = stats.totalEvents || 0
  document.getElementById("threats-detected").textContent = stats.threatsDetected || 0
  // Show unique IPs from events for Active IPs
  const uniqueIPs = [...new Set(this.events.flatMap((e) => [e.sourceIP, e.destinationIP]))]
  document.getElementById("active-connections").textContent = uniqueIPs.length
  document.getElementById("blocked-connections").textContent = stats.blockedConnections || 0

    // Calculate and show trends
    this.updateStatsTrends(stats)

    // Update performance bars
    const cpuUsage = stats.cpuUsage || 0
    const memoryUsage = stats.memoryUsage || 0
    const networkThroughput = stats.networkThroughput || 0

    document.getElementById("cpu-usage").textContent = `${cpuUsage.toFixed(1)}%`
    document.getElementById("cpu-bar").style.width = `${cpuUsage}%`

    document.getElementById("memory-usage").textContent = `${memoryUsage.toFixed(1)}%`
    document.getElementById("memory-bar").style.width = `${memoryUsage}%`

    document.getElementById("network-throughput").textContent = `${networkThroughput.toFixed(1)} Mbps`
    document.getElementById("network-bar").style.width = `${Math.min(networkThroughput, 100)}%`

    // Store for trend calculation
    this.previousStats = stats
  }

  updateStatsTrends(currentStats) {
    if (!this.previousStats) return

    const trends = [
      { id: "events-trend", current: currentStats.totalEvents, previous: this.previousStats.totalEvents },
      { id: "threats-trend", current: currentStats.threatsDetected, previous: this.previousStats.threatsDetected },
      {
        id: "connections-trend",
        current: currentStats.activeConnections,
        previous: this.previousStats.activeConnections,
      },
      {
        id: "blocked-trend",
        current: currentStats.blockedConnections,
        previous: this.previousStats.blockedConnections,
      },
    ]

    trends.forEach((trend) => {
      const element = document.getElementById(trend.id)
      if (trend.previous > 0) {
        const change = (((trend.current - trend.previous) / trend.previous) * 100).toFixed(1)
        const isIncrease = change > 0

        element.textContent = `${isIncrease ? "↑" : "↓"} ${Math.abs(change)}%`
        element.className = `stat-trend ${isIncrease ? "trend-up" : "trend-down"}`
        element.classList.remove("hidden")
      }
    })
  }

  addNewEvent(eventData) {
    this.events.unshift(eventData)
    if (this.events.length > 200) {
      this.events = this.events.slice(0, 200)
    }

    this.renderEvents()

    // Show alert banner for high/critical threats
    if (eventData.threatLevel === "HIGH" || eventData.threatLevel === "CRITICAL") {
      this.showAlertBanner(`${eventData.threatLevel} threat detected from ${eventData.sourceIP}`)
    }

    // Update real-time charts if visible
    if (document.getElementById("analytics-tab").classList.contains("active")) {
      this.updateAnalyticsCharts()
    }
  }

  addNewAlert(alertData) {
    this.alerts.unshift(alertData)
    if (this.alerts.length > 50) {
      this.alerts = this.alerts.slice(0, 50)
    }
    this.renderAlerts()
  }

  showAlertBanner(message) {
    const banner = document.getElementById("alert-banner")
    const messageElement = document.getElementById("alert-message")
    messageElement.textContent = message
    banner.classList.remove("hidden")

    setTimeout(() => {
      banner.classList.add("hidden")
    }, 10000)
  }

  showNotificationToast(alertData) {
    const toast = document.createElement("div")
    toast.className = `notification-toast ${alertData.severity.toLowerCase()}`
    toast.innerHTML = `
            <h4>${alertData.title}</h4>
            <p>${alertData.description}</p>
            <small>${new Date().toLocaleTimeString()}</small>
        `

    document.body.appendChild(toast)

    setTimeout(() => {
      toast.remove()
    }, 5000)
  }

  filterEvents() {
    const filteredEvents = this.events.filter((event) => {
      const matchesSearch =
        !this.eventFilters.search ||
        event.sourceIP.toLowerCase().includes(this.eventFilters.search) ||
        event.destinationIP.toLowerCase().includes(this.eventFilters.search) ||
        event.protocol.toLowerCase().includes(this.eventFilters.search) ||
        event.eventType.toLowerCase().includes(this.eventFilters.search)

      const matchesThreatLevel = !this.eventFilters.threatLevel || event.threatLevel === this.eventFilters.threatLevel

      return matchesSearch && matchesThreatLevel
    })

    this.renderFilteredEvents(filteredEvents)
  }

  renderEvents() {
    this.renderFilteredEvents(this.events)
  }

  renderFilteredEvents(events) {
    const eventsList = document.getElementById("events-list")
    const eventCount = document.getElementById("event-count")

    eventCount.textContent = `(${events.length} events)`

    if (events.length === 0) {
      eventsList.innerHTML = `
                <div style="text-align: center; color: #94a3b8; padding: 2rem;">
                    No events match the current filters. ${!this.monitoring ? "Start monitoring to see network activity." : ""}
                </div>
            `
      return
    }

    eventsList.innerHTML = events
      .map(
        (event) => `
            <div class="event-item ${event.threatLevel.toLowerCase()}">
                <div class="event-info">
                    <div class="threat-indicator threat-${event.threatLevel.toLowerCase()}"></div>
                    <div>
                        <div style="font-weight: 600; color: #ec4899;">
                            ${event.eventType.replace("_", " ")}
                            <span style="background: #374151; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; margin-left: 0.5rem;">
                                ${event.threatLevel}
                            </span>
                            ${
                              event.confidenceScore
                                ? `<span style="color: #94a3b8; font-size: 0.75rem; margin-left: 0.5rem;">
                                Confidence: ${(event.confidenceScore * 100).toFixed(1)}%
                            </span>`
                                : ""
                            }
                        </div>
                        <div class="event-details">
                            ${event.sourceIP} → ${event.destinationIP}:${event.destinationPort}
                            ${event.packetSize ? ` (${event.packetSize} bytes)` : ""}
                        </div>
                        ${
                          event.payloadInfo
                            ? `<div class="event-details" style="margin-top: 0.25rem; font-style: italic;">
                            ${event.payloadInfo.substring(0, 100)}${event.payloadInfo.length > 100 ? "..." : ""}
                        </div>`
                            : ""
                        }
                        <div class="event-actions">
                            <button class="btn btn-danger btn-small" onclick="dashboard.blockIP('${event.sourceIP}')">
                                Block IP
                            </button>
                            <button class="btn btn-secondary btn-small" onclick="dashboard.investigateEvent('${event.id}')">
                                Investigate
                            </button>
                        </div>
                    </div>
                </div>
                <div class="event-meta">
                    <div style="font-weight: 600;">${event.protocol}</div>
                    <div>${new Date(event.timestamp).toLocaleTimeString()}</div>
                    ${event.blocked ? '<div style="color: #dc2626; font-size: 0.75rem;">BLOCKED</div>' : ""}
                </div>
            </div>
        `,
      )
      .join("")
  }

  renderAlerts() {
    const alertsList = document.getElementById("alerts-list")

    if (this.alerts.length === 0) {
      alertsList.innerHTML = `
                <div style="text-align: center; color: #94a3b8; padding: 2rem;">
                    No alerts generated yet.
                </div>
            `
      return
    }

    alertsList.innerHTML = this.alerts
      .map(
        (alert) => `
            <div class="event-item ${alert.severity.toLowerCase()}">
                <div class="event-info">
                    <div class="threat-indicator threat-${alert.severity.toLowerCase()}"></div>
                    <div>
                        <div style="font-weight: 600; color: #ec4899;">
                            ${alert.title}
                            <span style="background: #374151; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; margin-left: 0.5rem;">
                                ${alert.severity}
                            </span>
                        </div>
                        <div class="event-details">
                            ${alert.description}
                        </div>
                        <div class="event-actions">
                            <button class="btn btn-primary btn-small" onclick="dashboard.acknowledgeAlert('${alert.id}')">
                                Acknowledge
                            </button>
                            <button class="btn btn-secondary btn-small" onclick="dashboard.resolveAlert('${alert.id}')">
                                Resolve
                            </button>
                        </div>
                    </div>
                </div>
                <div class="event-meta">
                    <div style="font-weight: 600;">Events: ${alert.eventCount}</div>
                    <div>${new Date(alert.timestamp).toLocaleTimeString()}</div>
                    ${alert.acknowledged ? '<div style="color: #34d399; font-size: 0.75rem;">ACKNOWLEDGED</div>' : ""}
                </div>
            </div>
        `,
      )
      .join("")
  }

  switchTab(tabName) {
    // Update tab buttons
    document.querySelectorAll(".tab-button").forEach((button) => {
      button.classList.remove("active")
    })
    const tabButton = document.querySelector(`[data-tab="${tabName}"]`)
    if (tabButton) {
      tabButton.classList.add("active")
    } else {
      console.warn(`Tab button for '${tabName}' not found.`)
    }

    // Update tab content
    document.querySelectorAll(".tab-content").forEach((content) => {
      content.classList.add("hidden")
    })
    const tabContent = document.getElementById(`${tabName}-tab`)
    if (tabContent) {
      tabContent.classList.remove("hidden")
    } else {
      console.warn(`Tab content for '${tabName}-tab' not found.`)
    }

    // Load tab-specific data
    switch (tabName) {
      case "analytics":
        this.renderAnalytics()
        break
      case "topology":
        this.renderNetworkTopology()
        break
      case "intelligence":
        this.renderThreatIntelligence()
        break
    }
  }

  renderAnalytics() {
    this.updateAnalyticsCharts()
  }

  updateAnalyticsCharts() {
    // Protocol distribution chart
    const protocolCounts = {}
    this.events.forEach((event) => {
      protocolCounts[event.protocol] = (protocolCounts[event.protocol] || 0) + 1
    })

    const protocolData = [
      {
        labels: Object.keys(protocolCounts),
        values: Object.values(protocolCounts),
        type: "pie",
        marker: { colors: ["#ec4899", "#f59e0b", "#3b82f6", "#34d399", "#8b5cf6"] },
      },
    ]

    Plotly.newPlot("protocol-chart", protocolData, {
      title: { text: "Protocol Distribution", font: { color: "#ffffff" } },
      paper_bgcolor: "transparent",
      plot_bgcolor: "transparent",
      font: { color: "#ffffff" },
    })

    // Traffic timeline
    const hourlyData = {}
    this.events.forEach((event) => {
      const hour = new Date(event.timestamp).getHours()
      hourlyData[hour] = (hourlyData[hour] || 0) + 1
    })

    const timelineData = [
      {
        x: Array.from({ length: 24 }, (_, i) => `${i}:00`),
        y: Array.from({ length: 24 }, (_, i) => hourlyData[i] || 0),
        type: "scatter",
        mode: "lines+markers",
        line: { color: "#ec4899" },
        marker: { color: "#ec4899" },
      },
    ]

    Plotly.newPlot("traffic-timeline", timelineData, {
      title: { text: "24-Hour Traffic Timeline", font: { color: "#ffffff" } },
      paper_bgcolor: "transparent",
      plot_bgcolor: "transparent",
      font: { color: "#ffffff" },
      xaxis: { color: "#ffffff" },
      yaxis: { color: "#ffffff", title: "Events per Hour" },
    })

    // Threat level heatmap
    const threatMatrix = this.generateThreatHeatmapData()
    const heatmapData = [
      {
        z: threatMatrix.values,
        x: threatMatrix.hours,
        y: threatMatrix.levels,
        type: "heatmap",
        colorscale: [
          [0, "#1e293b"],
          [0.25, "#3b82f6"],
          [0.5, "#f59e0b"],
          [0.75, "#dc2626"],
          [1, "#7c2d12"],
        ],
      },
    ]

    Plotly.newPlot("threat-heatmap", heatmapData, {
      title: { text: "Threat Level Heatmap (24 Hours)", font: { color: "#ffffff" } },
      paper_bgcolor: "transparent",
      plot_bgcolor: "transparent",
      font: { color: "#ffffff" },
      xaxis: { title: "Hour of Day", color: "#ffffff" },
      yaxis: { title: "Threat Level", color: "#ffffff" },
    })
  }

  generateThreatHeatmapData() {
    const levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    const hours = Array.from({ length: 24 }, (_, i) => i)
    const matrix = levels.map(() => new Array(24).fill(0))

    this.events.forEach((event) => {
      const hour = new Date(event.timestamp).getHours()
      const levelIndex = levels.indexOf(event.threatLevel)
      if (levelIndex !== -1) {
        matrix[levelIndex][hour]++
      }
    })

    return {
      values: matrix,
      hours: hours.map((h) => `${h}:00`),
      levels: levels,
    }
  }

  renderNetworkTopology() {
    // Simplified network topology visualization
    const topologyContainer = document.getElementById("network-topology")
    topologyContainer.innerHTML = `
            <div style="display: flex; justify-content: center; align-items: center; height: 100%; color: #94a3b8;">
                <div style="text-align: center;">
                    <div class="loading-spinner" style="margin: 0 auto 1rem;"></div>
                    <p>Loading network topology...</p>
                    <p style="font-size: 0.875rem; margin-top: 0.5rem;">
                        Analyzing ${this.events.length} network events
                    </p>
                </div>
            </div>
        `

    // Simulate topology loading
    setTimeout(() => {
      this.renderSimpleTopology()
    }, 2000)
  }

  renderSimpleTopology() {
    const uniqueIPs = [...new Set(this.events.flatMap((e) => [e.sourceIP, e.destinationIP]))]
    const topologyContainer = document.getElementById("network-topology")

    topologyContainer.innerHTML = `
            <div style="padding: 2rem; text-align: center;">
                <h4 style="color: #ec4899; margin-bottom: 1rem;">Network Overview</h4>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
                    <div style="background: #475569; padding: 1rem; border-radius: 0.5rem;">
                        <h5 style="color: #34d399;">Active IPs</h5>
                        <div style="font-size: 1.5rem; font-weight: bold;">${uniqueIPs.length}</div>
                    </div>
                    <div style="background: #475569; padding: 1rem; border-radius: 0.5rem;">
                        <h5 style="color: #f59e0b;">Connections</h5>
                        <div style="font-size: 1.5rem; font-weight: bold;">${this.events.length}</div>
                    </div>
                    <div style="background: #475569; padding: 1rem; border-radius: 0.5rem;">
                        <h5 style="color: #dc2626;">Threats</h5>
                        <div style="font-size: 1.5rem; font-weight: bold;">
                            ${this.events.filter((e) => e.threatLevel === "HIGH" || e.threatLevel === "CRITICAL").length}
                        </div>
                    </div>
                </div>
                <div style="margin-top: 2rem;">
                    <h5 style="color: #ec4899; margin-bottom: 1rem;">Top Source IPs</h5>
                    <div style="max-height: 200px; overflow-y: auto;">
                        ${this.getTopSourceIPs()
                          .map(
                            (ip) => `
                            <div style="display: flex; justify-content: space-between; padding: 0.5rem; border-bottom: 1px solid #475569;">
                                <span>${ip.ip}</span>
                                <span>${ip.count} events</span>
                            </div>
                        `,
                          )
                          .join("")}
                    </div>
                </div>
            </div>
        `
  }

  getTopSourceIPs() {
    const ipCounts = {}
    this.events.forEach((event) => {
      ipCounts[event.sourceIP] = (ipCounts[event.sourceIP] || 0) + 1
    })

    return Object.entries(ipCounts)
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10)
  }

  async loadThreatIntelligence() {
    try {
      // Simulate threat intelligence loading
      const activeThreats = this.events
        .filter((e) => e.threatLevel === "HIGH" || e.threatLevel === "CRITICAL")
        .slice(0, 5)

      const suspiciousIPs = this.getTopSourceIPs()
        .filter((ip) => ip.count > 10)
        .slice(0, 5)

      const attackPatterns = this.getAttackPatterns().slice(0, 5)

      this.updateThreatIntelligenceDisplay({
        activeThreats,
        suspiciousIPs,
        attackPatterns,
      })
    } catch (error) {
      console.error("Error loading threat intelligence:", error)
    }
  }

  getAttackPatterns() {
    const patterns = {}
    this.events.forEach((event) => {
      if (event.eventType !== "NORMAL") {
        patterns[event.eventType] = (patterns[event.eventType] || 0) + 1
      }
    })

    return Object.entries(patterns)
      .map(([pattern, count]) => ({ pattern, count }))
      .sort((a, b) => b.count - a.count)
  }

  updateThreatIntelligenceDisplay(data) {
    // Update active threats
    const activeThreatsElement = document.getElementById("active-threats-list")
    if (data.activeThreats && data.activeThreats.length > 0) {
      activeThreatsElement.innerHTML = data.activeThreats
        .map((threat) => `<li>${threat.eventType} from ${threat.sourceIP} (${threat.threatLevel})</li>`)
        .join("")
    } else {
      activeThreatsElement.innerHTML = "<li>No active threats detected</li>"
    }

    // Update suspicious IPs
    const suspiciousIPsElement = document.getElementById("suspicious-ips-list")
    if (data.suspiciousIPs && data.suspiciousIPs.length > 0) {
      suspiciousIPsElement.innerHTML = data.suspiciousIPs.map((ip) => `<li>${ip.ip} (${ip.count} events)</li>`).join("")
    } else {
      suspiciousIPsElement.innerHTML = "<li>No suspicious IPs identified</li>"
    }

    // Update attack patterns
    const attackPatternsElement = document.getElementById("attack-patterns-list")
    if (data.attackPatterns && data.attackPatterns.length > 0) {
      attackPatternsElement.innerHTML = data.attackPatterns
        .map((pattern) => `<li>${pattern.pattern.replace("_", " ")} (${pattern.count} occurrences)</li>`)
        .join("")
    } else {
      attackPatternsElement.innerHTML = "<li>No attack patterns detected</li>"
    }
  }

  renderThreatIntelligence() {
    const intelligenceContainer = document.getElementById("intelligence-dashboard")
    intelligenceContainer.innerHTML = `
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem;">
                <div class="intel-card">
                    <h4>Behavioral Analysis</h4>
                    <p style="color: #94a3b8; margin: 1rem 0;">
                        Advanced behavioral patterns detected in network traffic.
                    </p>
                    <div style="background: #475569; padding: 1rem; border-radius: 0.375rem;">
                        <div>Anomaly Score: <strong style="color: #f59e0b;">0.73</strong></div>
                        <div>Risk Level: <strong style="color: #dc2626;">HIGH</strong></div>
                    </div>
                </div>
                <div class="intel-card">
                    <h4>Pattern Recognition</h4>
                    <p style="color: #94a3b8; margin: 1rem 0;">
                        Machine learning analysis of attack patterns.
                    </p>
                    <div style="background: #475569; padding: 1rem; border-radius: 0.375rem;">
                        <div>Patterns Identified: <strong>${this.getAttackPatterns().length}</strong></div>
                        <div>Confidence: <strong style="color: #34d399;">0.89</strong></div>
                    </div>
                </div>
                <div class="intel-card">
                    <h4>Threat Correlation</h4>
                    <p style="color: #94a3b8; margin: 1rem 0;">
                        Real-time correlation of security events.
                    </p>
                    <div style="background: #475569; padding: 1rem; border-radius: 0.375rem;">
                        <div>Correlated Events: <strong>${this.events.filter((e) => e.threatLevel !== "LOW").length}</strong></div>
                        <div>Active Scenarios: <strong style="color: #f59e0b;">3</strong></div>
                    </div>
                </div>
            </div>
        `
  }

  toggleAutoRefresh() {
    this.autoRefresh = !this.autoRefresh
    const button = document.getElementById("auto-refresh-toggle")
    button.textContent = this.autoRefresh ? "Disable" : "Enable"
    button.className = this.autoRefresh ? "btn btn-primary" : "btn btn-secondary"
  }

  async blockIP(ip) {
    try {
      const response = await fetch("/api/security/block-ip", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip }),
      })

      const result = await response.json()
      if (result.status === "success") {
        this.showNotificationToast({
          title: "IP Blocked",
          description: `Successfully blocked ${ip}`,
          severity: "LOW",
        })
      }
    } catch (error) {
      console.error("Error blocking IP:", error)
    }
  }

  investigateEvent(eventId) {
    // Placeholder for event investigation
    this.showNotificationToast({
      title: "Investigation Started",
      description: `Investigating event ${eventId}`,
      severity: "LOW",
    })
  }

  acknowledgeAlert(alertId) {
    // Placeholder for alert acknowledgment
    this.showNotificationToast({
      title: "Alert Acknowledged",
      description: `Alert ${alertId} has been acknowledged`,
      severity: "LOW",
    })
  }

  resolveAlert(alertId) {
    // Placeholder for alert resolution
    this.showNotificationToast({
      title: "Alert Resolved",
      description: `Alert ${alertId} has been resolved`,
      severity: "LOW",
    })
  }

  refreshNetworkTopology() {
    this.renderNetworkTopology()
  }

  resetTopologyZoom() {
    // Placeholder for topology zoom reset
    console.log("Topology zoom reset")
  }
}

// Global functions
function closeAlertBanner() {
  document.getElementById("alert-banner").classList.add("hidden")
}

// Initialize dashboard when DOM is loaded
let dashboard
document.addEventListener("DOMContentLoaded", () => {
  dashboard = new AdvancedIDSDashboard()
})

