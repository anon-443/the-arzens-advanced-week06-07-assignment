output "vpc_id" { value = aws_vpc.main.id }
output "security_group_id" { value = aws_security_group.web.id }
output "s3_bucket_name" { value = aws_s3_bucket.artifacts.bucket }
output "instance_id" { value = aws_instance.web.id }
output "instance_private_ip" { value = aws_instance.web.private_ip }
