import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.event.*;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import javax.swing.*;

public class gui extends JFrame implements ActionListener {
    private static final long serialVersionUID = 1L;
    private ProxyServer proxyServer;
    private JLabel statusLabel;

    gui() {
        this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        this.setSize(1000, 500);
        this.setLayout(new BorderLayout());
        this.setTitle("Transparent Proxy");
        JMenuBar menuBar = new JMenuBar();

        JMenu file = new JMenu("File");
        JMenu help = new JMenu("Help");

        JMenuItem start = new JMenuItem("Start");
        JMenuItem stop = new JMenuItem("Stop");
        JMenuItem report = new JMenuItem("Report");
        JMenuItem addHostToFilter = new JMenuItem("Add host to filter");
        JMenuItem displayCurrentFilteredHosts = new JMenuItem("Display current filtered hosts");
        JMenuItem exit = new JMenuItem("Exit");

        JMenuItem about = new JMenuItem("About");

        file.add(start);
        file.add(stop);
        file.add(report);
        file.add(addHostToFilter);
        file.add(displayCurrentFilteredHosts);
        file.add(exit);

        help.add(about);

        menuBar.add(file);
        menuBar.add(help);
        this.setJMenuBar(menuBar);

        statusLabel = new JLabel("ProxyServer is not running.", SwingConstants.CENTER);
        statusLabel.setFont(new Font("Arial", Font.BOLD, 20)); 
        this.add(statusLabel, BorderLayout.CENTER);

        this.setVisible(true);

        start.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (proxyServer != null) {
                    System.out.println("Proxy Server is already running.");
                } else {
                    proxyServer = new ProxyServer();
                    proxyServer.start();
                    statusLabel.setText("ProxyServer is running.");
                }
            }
        });

        stop.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (proxyServer != null) {
                    proxyServer.stopServer();
                    proxyServer = null;
                    statusLabel.setText("ProxyServer is not running.");
                    System.out.println("Proxy server stopped.");
                } else {
                    System.out.println("Proxy server is not running.");
                }
            }
        });

        addHostToFilter.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String domain = JOptionPane.showInputDialog(gui.this, "Enter domain to filter:");
                if (domain != null) {
                    if (!domain.isEmpty() && domain.contains(".")) {
                        ProxyHandler.filteredDomains.add(domain);
                    } else {
                        JOptionPane.showMessageDialog(gui.this, "Please enter a valid domain.");
                    }
                }
            }
        });

        displayCurrentFilteredHosts.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (ProxyHandler.filteredDomains == null || ProxyHandler.filteredDomains.isEmpty()) {
                    JOptionPane.showMessageDialog(gui.this, "No filtered domains.");
                } else {
                    StringBuilder filteredHostsStringBuilder = new StringBuilder();
                    filteredHostsStringBuilder.append("Current Filtered Hosts:\n");
                    for (String host : ProxyHandler.filteredDomains) {
                        filteredHostsStringBuilder.append(host).append("\n");
                    }
                    JOptionPane.showMessageDialog(gui.this, filteredHostsStringBuilder.toString());
                }
            }
        });

        report.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String ipAddress = JOptionPane.showInputDialog(gui.this, "Enter IP address to filter:");
                if (ipAddress != null && !ipAddress.isEmpty()) {
                    String logs = getLogsForIp(ipAddress);
                    if (logs.isEmpty()) {
                        JOptionPane.showMessageDialog(gui.this, "No logs found for IP: " + ipAddress);
                    } else {
                        JOptionPane.showMessageDialog(gui.this, logs);
                    }
                }
            }
        });

        about.addActionListener(this);
        exit.addActionListener(this);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getActionCommand().equals("About")) {
            JOptionPane.showMessageDialog(this, "Yahya Koyuncu\n" + "20200702058\n" + "yahya.koyuncu@std.yeditepe.edu.tr");
        } else if (e.getActionCommand().equals("Exit")) {
            System.exit(0);
        }
    }

    private String getLogsForIp(String ipAddress) {
        StringBuilder logs = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader("log.txt"))) {
            String line;
            boolean include = false;
            while ((line = reader.readLine()) != null) {
                if (line.contains("Ip Addr: " + ipAddress)) {
                    include = true;
                }
                if (include) {
                    logs.append(line).append("\n");
                }
                if (line.equals("@@@")) {
                    include = false;
                }
            }
        } catch (IOException e) {
            System.out.println("No such file or directory");
        }
        return logs.toString();
    }

    
}
