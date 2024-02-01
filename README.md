# firewall
sudo venv/bin/python app.py
curl -d "param1=value1&param2=<scrip<script>>>alealertrt('XSS')</scrip</script>>" -X POST http://10.0.1.1/
curl -d "username=admin' OR '1'='1'--&password=doesntmatter" -X POST http://10.0.1.1/
