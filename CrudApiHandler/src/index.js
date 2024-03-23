const DynamicCrudEndpoint = require("./crud"); 
const app = new DynamicCrudEndpoint();
app.setupEndpoints("bot_users");
app.start(4039);