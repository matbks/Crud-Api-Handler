const DynamicCrudEndpoint = require("./crud"); 
const app = new DynamicCrudEndpoint();
app.setupEndpoints("users");
app.start(4039);