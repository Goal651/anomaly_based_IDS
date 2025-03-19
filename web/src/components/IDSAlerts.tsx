import { useEffect, useState } from "react";
import { Card } from "@/components/ui/card";
import { Table, TableHead, TableRow, TableCell, TableBody } from "@/components/ui/table";
import { AlertCircle } from "lucide-react";
import axios from "axios";

export default function IDSAlerts() {
    const [alerts, setAlerts] = useState([]);

    useEffect(() => {
        const fetchAlerts = async () => {
            try {
                const response = await axios.get("http://localhost:8000/alerts");
                setAlerts(response.data);
            } catch (error) {
                console.error("Error fetching alerts:", error);
            }
        };

        fetchAlerts();
        const interval = setInterval(fetchAlerts, 3000);
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="p-6">
            <Card className="p-4 shadow-md">
                <h2 className="text-xl font-semibold mb-4 flex items-center">
                    <AlertCircle className="text-red-500 mr-2" /> Intrusion Alerts
                </h2>
                <Table>
                    <TableHead>
                        <TableRow>
                            <TableCell>Source</TableCell>
                            <TableCell>Destination</TableCell>
                            <TableCell>Protocol</TableCell>
                            <TableCell>Info</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {alerts.map((alert, index) => (
                            <TableRow key={index}>
                                <TableCell>{alert.source}</TableCell>
                                <TableCell>{alert.destination}</TableCell>
                                <TableCell>{alert.protocol}</TableCell>
                                <TableCell>{alert.info}</TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </Card>
        </div>
    );
}
