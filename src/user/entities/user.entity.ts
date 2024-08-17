import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({
    nullable: false,
  })
  nickName: string;

  @Column({
    nullable: true,
  })
  firstName: string;

  @Column({
    nullable: true,
  })
  lastName: string;

  @Column()
  password: string;

  @Column({
    nullable: false,
  })
  provider: string;
}
