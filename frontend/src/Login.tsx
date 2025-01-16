import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

const Login: React.FC = () => {
  const [pseudoIdentity, setPseudoIdentity] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleLogin = () => {
    // Simulate a successful login
    if (pseudoIdentity) {
      setError('');
      navigate('/dashboard'); // Redirect to the dashboard
    } else {
      setError('Please enter a pseudo identity.');
    }
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1>Login</h1>
        <input
          type="text"
          value={pseudoIdentity}
          onChange={(e) => setPseudoIdentity(e.target.value)}
          placeholder="Enter Pseudo Identity"
        />
        <button onClick={handleLogin}>Login</button>
        {error && <p>{error}</p>}
      </header>
    </div>
  );
};

export default Login; 