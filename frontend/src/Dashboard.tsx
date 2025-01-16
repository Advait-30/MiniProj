import React from 'react';

const Dashboard: React.FC = () => {
  // Mock data to display
  const mockData = [
    { id: 1, type: 'Heart Rate', value: '72 bpm' },
    { id: 2, type: 'Temperature', value: '36.6 °C' },
    { id: 3, type: 'Blood Pressure', value: '120/80 mmHg' },
  ];

  return (
    <div className="App">
      <header className="App-header">
        <h1>Dashboard</h1>
        <h2>Your Health Data</h2>
        <ul>
          {mockData.map((data) => (
            <li key={data.id}>
              {data.type}: {data.value}
            </li>
          ))}
        </ul>
      </header>
    </div>
  );
};

export default Dashboard; 